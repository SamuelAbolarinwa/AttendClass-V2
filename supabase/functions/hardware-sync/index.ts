/**
 * hardware-sync — Supabase Edge Function
 *
 * Secure upload endpoint for attendance terminals (ESP32).
 * Supports:
 *   1. Cryptographically verified offline signed BLE attendance records.
 *   2. Legacy attendance CSV imports.
 *   3. Legacy enrollment CSV imports (mandatory RFID AND Fingerprint 2FA).
 *
 * AUTHENTICATION:
 *   x-device-key: static per-device secret (hashed with SHA-256 and matched against devices.device_key_hash)
 *   x-sync-file-type: "attendance" | "enrollment" | "signed_attendance"
 */

import { createClient, SupabaseClient } from "jsr:@supabase/supabase-js@2";

// ─── Cryptographic & Encoding Helpers ────────────────────────────────────────

/** SHA-256 hex digest — used to compare x-device-key against devices.device_key_hash */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Decode Base64 string to Uint8Array */
function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const SPKI_P256_PREFIX_HEX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
const SECP256R1_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const SECP256R1_HALF_N = SECP256R1_N >> 1n;

/** Validate uncompressed NIST P-256 SPKI public key (91 bytes) */
function validateSpkiP256(pubKeyBytes: Uint8Array): boolean {
  if (pubKeyBytes.length !== 91) return false;
  let prefixHex = "";
  for (let i = 0; i < 26; i++) {
    prefixHex += pubKeyBytes[i].toString(16).padStart(2, "0");
  }
  if (prefixHex !== SPKI_P256_PREFIX_HEX) return false;
  if (pubKeyBytes[26] !== 0x04) return false;
  return true;
}

/** Convert ASN.1 DER ECDSA signature into 64-byte raw (R || S) format for WebCrypto with low-S canonicality */
function derToCompactSignature(derBytes: Uint8Array): Uint8Array {
  if (derBytes.length === 64) {
    const sHex = Array.from(derBytes.subarray(32, 64)).map((b) => b.toString(16).padStart(2, "0")).join("");
    const s = BigInt("0x" + sHex);
    if (s > SECP256R1_HALF_N) {
      const canonicalS = SECP256R1_N - s;
      const res = new Uint8Array(derBytes);
      const sCleanHex = canonicalS.toString(16).padStart(64, "0");
      for (let i = 0; i < 32; i++) {
        res[32 + i] = parseInt(sCleanHex.substr(i * 2, 2), 16);
      }
      return res;
    }
    return derBytes;
  }

  let offset = 2;
  if (derBytes[0] !== 0x30) throw new Error("Invalid ASN.1 DER sequence");
  if (derBytes[1] & 0x80) {
    const lenBytes = derBytes[1] & 0x7f;
    offset = 2 + lenBytes;
  }
  if (derBytes[offset++] !== 0x02) throw new Error("Expected INTEGER tag for R");
  const rLen = derBytes[offset++];
  const rBytes = derBytes.subarray(offset, offset + rLen);
  offset += rLen;
  if (derBytes[offset++] !== 0x02) throw new Error("Expected INTEGER tag for S");
  const sLen = derBytes[offset++];
  const sBytes = derBytes.subarray(offset, offset + sLen);

  const raw = new Uint8Array(64);
  const rClean = (rBytes[0] === 0x00 && rBytes.length === 33) ? rBytes.subarray(1) : rBytes;
  raw.set(rClean, 32 - rClean.length);
  const sClean = (sBytes[0] === 0x00 && sBytes.length === 33) ? sBytes.subarray(1) : sBytes;
  raw.set(sClean, 64 - sClean.length);

  const sHex = Array.from(raw.subarray(32, 64)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const s = BigInt("0x" + sHex);
  if (s > SECP256R1_HALF_N) {
    const canonicalS = SECP256R1_N - s;
    const sCleanHex = canonicalS.toString(16).padStart(64, "0");
    for (let i = 0; i < 32; i++) {
      raw[32 + i] = parseInt(sCleanHex.substr(i * 2, 2), 16);
    }
  }
  return raw;
}

/** Convert 64-byte raw (R || S) signature into ASN.1 DER format */
function compactToDerSignature(compactBytes: Uint8Array): Uint8Array {
  if (compactBytes.length !== 64) {
    throw new Error(`Expected 64-byte signature, got ${compactBytes.length}`);
  }
  function toIntegerDer(bytes: Uint8Array): number[] {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = Array.from(bytes.subarray(start));
    if (trimmed[0] >= 0x80) trimmed.unshift(0x00);
    return [0x02, trimmed.length, ...trimmed];
  }
  const rDer = toIntegerDer(compactBytes.subarray(0, 32));
  const sDer = toIntegerDer(compactBytes.subarray(32, 64));
  const body = [...rDer, ...sDer];
  return new Uint8Array([0x30, body.length, ...body]);
}

/** Verify ECDSA P-256 SHA-256 signature against X.509 SPKI public key */
async function verifyP256Signature(
  canonicalMessage: string,
  signatureBase64: string,
  publicKeySpkiBase64: string,
): Promise<boolean> {
  try {
    const pubKeyBytes = base64ToBytes(publicKeySpkiBase64);
    if (!validateSpkiP256(pubKeyBytes)) {
      console.error("Invalid SPKI public key structure or curve");
      return false;
    }
    const sigBytes = base64ToBytes(signatureBase64);
    const compactSig = derToCompactSignature(sigBytes);
    const msgBytes = new TextEncoder().encode(canonicalMessage);

    const cryptoKey = await crypto.subtle.importKey(
      "spki",
      pubKeyBytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      compactSig,
      msgBytes,
    );
  } catch (err: unknown) {
    console.error("P-256 verification error:", err);
    return false;
  }
}

/** Trim surrounding quotes from a CSV field. */
function unquote(field: string): string {
  const trimmed = field.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/""/g, '"');
  }
  return trimmed;
}

/** Simple CSV line splitter. */
function splitCSVLine(line: string): string[] {
  return line.split(",").map(unquote);
}

/** Build a JSON response. */
function json(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ─── Row Processors ──────────────────────────────────────────────────────────

interface ProcessResult {
  ok: boolean;
  duplicate?: boolean;
  warning?: string;
}

/**
 * Process a cryptographically signed offline attendance record.
 * Validates terminal identity, student profile, active device enrolment,
 * canonical signature, and idempotency by event_id.
 */
async function processSignedAttendanceRow(
  supabase: SupabaseClient,
  raw: Record<string, string>,
  uploadingTerminalId: string,
): Promise<ProcessResult> {
  const eventId = raw.event_id?.trim();
  const matric = raw.matric_number?.trim();
  const terminalId = raw.terminal_id?.trim() || "TERM_OFFLINE";
  const sessionId = raw.session_id?.trim() || null;
  const challenge = raw.challenge?.trim() || "";
  const signature = raw.signature?.trim();
  const publicKey = raw.public_key?.trim();
  const credentialId = raw.credential_id?.trim() || "";
  const credentialVersion = raw.credential_version?.trim() || "v1";
  const timestamp = parseInt(raw.timestamp || "0", 10);
  const timestampSource = raw.timestamp_source?.trim() || "phone_os";

  if (!eventId) {
    return { ok: false, warning: "Missing event_id in signed attendance record" };
  }
  if (!matric) {
    return { ok: false, warning: "Missing matric_number in signed attendance record" };
  }
  if (!signature || !publicKey) {
    return { ok: false, warning: `Missing signature or public_key for ${matric}` };
  }

  // 0. Terminal Matching: uploading terminal must match the record’s terminal_id
  if (terminalId !== uploadingTerminalId) {
    return {
      ok: false,
      warning: `TERMINAL_MISMATCH: Record terminal ${terminalId} does not match uploading terminal ${uploadingTerminalId}`,
    };
  }

  // Delimiter validation: security-sensitive fields must not contain pipe or newline
  const fieldsToValidate = [eventId, credentialId, credentialVersion, matric, terminalId, sessionId || "", challenge, timestampSource];
  for (const f of fieldsToValidate) {
    if (f.includes("|") || f.includes("\n") || f.includes("\r")) {
      return { ok: false, warning: "INVALID_DELIMITER: Canonical field cannot contain pipe or newline characters" };
    }
  }

  // 1. Idempotency & Conflict Check: detect conflicting duplicate event_id
  const { data: existingLog } = await supabase
    .from("attendance_logs")
    .select("id, student_id, terminal_id, method")
    .eq("event_id", eventId)
    .maybeSingle();

  if (existingLog) {
    const { data: stdProfile } = await supabase
      .from("profiles")
      .select("id")
      .eq("matric_number", matric)
      .maybeSingle();

    if (
      (stdProfile && existingLog.student_id !== stdProfile.id) ||
      (existingLog.terminal_id && existingLog.terminal_id !== terminalId)
    ) {
      return {
        ok: false,
        warning: `EVENT_ID_CONFLICT: Duplicate event_id ${eventId} submitted with conflicting student or terminal data`,
      };
    }
    return { ok: true, duplicate: true };
  }

  // 2. Look up student profile
  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id, matric_number")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr || !student) {
    return { ok: false, warning: `No student profile found for matric ${matric}` };
  }

  // 3. Verify active authorized device key for this student
  const { data: activeDevice, error: devErr } = await supabase
    .from("student_devices")
    .select("id, device_public_key, algorithm, revoked_at")
    .eq("student_id", student.id)
    .is("revoked_at", null)
    .order("enrolled_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (devErr || !activeDevice) {
    return { ok: false, warning: `No active enrolled device found for student ${matric}` };
  }

  if (activeDevice.device_public_key !== publicKey) {
    return { ok: false, warning: `Public key mismatch with enrolled key for student ${matric}` };
  }

  // 4. Cryptographic Signature Verification
  const canonicalMessage = [
    "v1",
    "submission",
    eventId,
    credentialId,
    credentialVersion,
    activeDevice.algorithm || "ECDSA_P256_SHA256",
    student.id,
    matric,
    terminalId,
    sessionId || "",
    challenge,
    timestamp.toString(),
    timestampSource,
  ].join("|");

  const isSigValid = await verifyP256Signature(canonicalMessage, signature, publicKey);
  if (!isSigValid) {
    return { ok: false, warning: `Cryptographic signature verification failed for student ${matric}` };
  }

  // 5. Preserved Timestamps
  const phoneTime = timestamp > 0 ? new Date(timestamp * 1000).toISOString() : new Date().toISOString();
  let terminalSavedAt: string | null = null;
  if (raw.terminal_saved_at) {
    try {
      const parsed = new Date(raw.terminal_saved_at);
      terminalSavedAt = isNaN(parsed.getTime()) ? null : parsed.toISOString();
    } catch {
      terminalSavedAt = null;
    }
  }

  // 6. Idempotent Insert into attendance_logs
  const { error: insertErr } = await supabase.from("attendance_logs").insert({
    session_id: sessionId,
    student_id: student.id,
    method: "ble_offline_signed",
    event_id: eventId,
    terminal_id: terminalId,
    terminal_saved_at: terminalSavedAt,
    phone_attendance_time: phoneTime,
    timestamp_source: timestampSource,
    offline_verified: true,
    verified_at: terminalSavedAt || phoneTime || new Date().toISOString(),
  });

  if (insertErr) {
    if (insertErr.code === "23505") { // unique constraint violation on event_id
      return { ok: true, duplicate: true };
    }
    return { ok: false, warning: `Insert failed for ${matric}: ${insertErr.message}` };
  }

  return { ok: true };
}

/**
 * Process a single legacy attendance CSV row.
 * CSV columns: Time, Name, Matric Number, Logging Type
 */
async function processAttendanceRow(
  supabase: SupabaseClient,
  raw: Record<string, string>,
): Promise<ProcessResult> {
  const matric = raw.matric_number?.trim();
  if (!matric) {
    return { ok: false, warning: "Empty matric number in attendance row" };
  }

  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr || !student) {
    return { ok: false, warning: `No student profile found for matric ${matric}` };
  }

  const loggingType = (raw.logging_type ?? "").trim().toUpperCase();
  // Mandatory 2FA check preservation: matched RFID AND fingerprint
  const method: string = loggingType === "QR_BLE" ? "qr_ble_legacy" : "2fa_rfid_fp";

  let verifiedAt: string;
  try {
    const parsed = new Date(raw.time);
    verifiedAt = isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
  } catch {
    verifiedAt = new Date().toISOString();
  }

  const { error: insertErr } = await supabase.from("attendance_logs").insert({
    session_id: null,
    student_id: student.id,
    method,
    verified_at: verifiedAt,
    offline_verified: false,
  });

  if (insertErr) {
    return { ok: false, warning: `Failed to insert legacy attendance log for ${matric}: ${insertErr.message}` };
  }

  return { ok: true };
}

/**
 * Process a single enrollment CSV row.
 * CSV columns: Time, Name, Matric Number, RFID, Fingerprint ID
 * Preserves mandatory terminal 2FA credentials.
 */
async function processEnrollmentRow(
  supabase: SupabaseClient,
  raw: Record<string, string>,
): Promise<ProcessResult> {
  const matric = raw.matric_number?.trim();
  if (!matric) {
    return { ok: false, warning: "Empty matric number in enrollment row" };
  }

  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr || !student) {
    return { ok: false, warning: `No student profile found for matric ${matric}` };
  }

  const rfidCardId = raw.rfid?.trim() || null;
  const fingerprintId = raw.fingerprint_id ? parseInt(raw.fingerprint_id.trim(), 10) : null;

  const { data: existing, error: fetchErr } = await supabase
    .from("student_credentials")
    .select("id, rfid_card_id, fingerprint_id")
    .eq("student_id", student.id)
    .maybeSingle();

  if (fetchErr) {
    return { ok: false, warning: `DB error fetching credentials for ${matric}: ${fetchErr.message}` };
  }

  if (existing) {
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (rfidCardId !== null) updates.rfid_card_id = rfidCardId;
    if (fingerprintId !== null && !isNaN(fingerprintId)) updates.fingerprint_id = fingerprintId;

    const { error: updateErr } = await supabase
      .from("student_credentials")
      .update(updates)
      .eq("id", existing.id);

    if (updateErr) {
      return { ok: false, warning: `Failed to update credentials for ${matric}: ${updateErr.message}` };
    }
  } else {
    const { error: insertErr } = await supabase
      .from("student_credentials")
      .insert({
        student_id: student.id,
        rfid_card_id: rfidCardId,
        fingerprint_id: fingerprintId !== null && !isNaN(fingerprintId) ? fingerprintId : null,
      });

    if (insertErr) {
      return { ok: false, warning: `Failed to insert credentials for ${matric}: ${insertErr.message}` };
    }
  }

  return { ok: true };
}

// ─── Main handler ────────────────────────────────────────────────────────────

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, x-sync-file-type, x-device-key",
      },
    });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const fileType = req.headers.get("x-sync-file-type");
  const deviceKey = req.headers.get("x-device-key");

  if (!deviceKey) {
    return json({ error: "Missing x-device-key header" }, 401);
  }
  if (!fileType || (fileType !== "attendance" && fileType !== "enrollment" && fileType !== "signed_attendance")) {
    return json({
      error: "Missing or invalid x-sync-file-type header (expected 'attendance', 'enrollment', or 'signed_attendance')",
    }, 400);
  }

  // Authenticate device via SHA-256 key hash
  const keyHash = await sha256Hex(deviceKey);
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const { data: device, error: deviceErr } = await supabase
    .from("devices")
    .select("id, device_id")
    .eq("device_key_hash", keyHash)
    .maybeSingle();

  if (deviceErr || !device) {
    console.error("Terminal device authentication failed");
    return json({ error: "Unauthorized — terminal key not recognized" }, 401);
  }

  console.log(`Authenticated terminal ${device.device_id} (${device.id})`);

  let body: string;
  try {
    body = await req.text();
  } catch {
    return json({ error: "Failed to read request body" }, 400);
  }

  if (!body.trim()) {
    return json({ error: "Empty request body" }, 400);
  }

  let rowsReceived = 0;
  let rowsProcessed = 0;
  let rowsFailed = 0;
  let duplicates = 0;
  const warnings: string[] = [];

  // Check if body is JSON array of signed attendance records
  const isJson = body.trim().startsWith("[") || body.trim().startsWith("{");
  if (isJson || fileType === "signed_attendance") {
    let records: Record<string, string>[] = [];
    try {
      const parsed = JSON.parse(body);
      records = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      // If not JSON, parse CSV format for signed attendance
      const lines = body.trim().split(/\r?\n/).filter((l) => l.trim().length > 0);
      records = lines.map((l) => {
        const c = splitCSVLine(l);
        return {
          event_id: c[0] ?? "",
          student_id: c[1] ?? "",
          matric_number: c[2] ?? "",
          terminal_id: c[3] ?? "",
          session_id: c[4] ?? "",
          timestamp: c[5] ?? "",
          terminal_saved_at: c[6] ?? "",
          public_key: c[7] ?? "",
          signature: c[8] ?? "",
          challenge: c[9] ?? "",
        };
      });
    }

    rowsReceived = records.length;
    for (const record of records) {
      const result = await processSignedAttendanceRow(supabase, record, device.device_id);
      if (result.ok) {
        if (result.duplicate) {
          duplicates++;
        } else {
          rowsProcessed++;
        }
      } else {
        rowsFailed++;
        if (result.warning) warnings.push(result.warning);
      }
    }
  } else {
    // Process legacy CSV
    const allLines = body.trim().split(/\r?\n/).filter((l) => l.trim().length > 0);
    const HEADER_RE = /^\s*time\s*,\s*name\s*,\s*matric/i;
    const dataLines = allLines.length > 0 && HEADER_RE.test(allLines[0]) ? allLines.slice(1) : allLines;

    rowsReceived = dataLines.length;
    for (const line of dataLines) {
      const cols = splitCSVLine(line);
      const rawRow: Record<string, string> =
        fileType === "attendance"
          ? {
              time: cols[0] ?? "",
              name: cols[1] ?? "",
              matric_number: cols[2] ?? "",
              logging_type: cols[3] ?? "",
            }
          : {
              time: cols[0] ?? "",
              name: cols[1] ?? "",
              matric_number: cols[2] ?? "",
              rfid: cols[3] ?? "",
              fingerprint_id: cols[4] ?? "",
            };

      const result =
        fileType === "attendance"
          ? await processAttendanceRow(supabase, rawRow)
          : await processEnrollmentRow(supabase, rawRow);

      if (result.ok) {
        rowsProcessed++;
      } else {
        rowsFailed++;
        if (result.warning) warnings.push(result.warning);
      }
    }
  }

  return json({
    accepted: rowsProcessed,
    duplicates,
    rejected: rowsFailed,
    rows_received: rowsReceived,
    rows_processed: rowsProcessed,
    rows_failed: rowsFailed,
    ...(warnings.length > 0 ? { warnings } : {}),
  });
});
