/**
 * hardware-sync — Supabase Edge Function
 *
 * Secure upload & sync endpoint for:
 *   1. Physical ESP32 Terminals (direct WiFi upload via x-device-key).
 *   2. Mobile Admin BLE Sync Bridge (course rep/admin phone via active admin_token).
 *   3. Active student credential registry provisioning (refresh_credentials / get_enrolled_keys).
 *   4. Legacy 2FA CSV imports (RFID + Fingerprint).
 *
 * AUTHENTICATION:
 *   Mode A (Hardware Direct):
 *     - Header 'x-device-key': static secret matched against devices.device_key_hash (SHA-256)
 *     - Header 'x-sync-file-type': "signed_attendance" | "attendance" | "enrollment"
 *     - Header 'x-sync-action': "refresh_credentials" (optional)
 *
 *   Mode B (Mobile Admin BLE Bridge):
 *     - JSON Body: { action: "sync_attendance_batch", admin_token: "<UUID>", terminal_id: "...", records: [...] }
 *     - Authenticated via active_sessions (valid, unexpired, role in ('administrator', 'manager'))
 *
 *   Mode C (Admin Provisioning Download):
 *     - JSON Body: { action: "get_enrolled_keys", admin_token: "<UUID>" }
 */

import { createClient, SupabaseClient } from "jsr:@supabase/supabase-js@2";

// ─── Cryptographic & Encoding Helpers ────────────────────────────────────────

/** SHA-256 hex digest */
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

/** Convert ASN.1 DER ECDSA signature into 64-byte raw (R || S) format with low-S canonicality */
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

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, x-sync-file-type, x-device-key, x-sync-action, authorization, apikey",
};

/** Build a JSON response with CORS headers. */
function json(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

// ─── Row Processors ──────────────────────────────────────────────────────────

export type RecordStatus = "ACCEPTED" | "DUPLICATE" | "REJECTED" | "RETRYABLE";

export interface ProcessResult {
  ok: boolean;
  status: RecordStatus;
  event_id?: string;
  matric_number?: string;
  reason?: string;
}

/**
 * Process a cryptographically signed offline attendance record.
 * Handles both full records (direct from terminal) and bridge records (via mobile admin).
 */
async function processSignedAttendanceRow(
  supabase: SupabaseClient,
  raw: Record<string, string>,
  uploadingTerminal: { id: string; device_id: string; public_key?: string | null; algorithm?: string },
): Promise<ProcessResult> {
  const uploadingTerminalId = uploadingTerminal.device_id;
  const eventId = raw.event_id?.trim();
  const matric = raw.matric_number?.trim();
  const terminalId = raw.terminal_id?.trim() || uploadingTerminalId;
  const sessionId = raw.session_id?.trim() || null;
  const challenge = raw.challenge?.trim() || "";
  const signature = raw.signature?.trim();
  const publicKey = raw.public_key?.trim();
  const credentialId = raw.credential_id?.trim() || "";
  const credentialVersion = raw.credential_version?.trim() || "v1";
  const timestamp = parseInt(raw.timestamp || "0", 10);
  const timestampSource = raw.timestamp_source?.trim() || "phone_os";
  const submissionDigest = raw.submission_digest?.trim();
  const termReceiptSig = raw.terminal_receipt_signature?.trim();

  if (!eventId) {
    return { ok: false, status: "REJECTED", reason: "Missing event_id in signed attendance record" };
  }
  if (!matric) {
    return { ok: false, status: "REJECTED", event_id: eventId, reason: "Missing matric_number in signed attendance record" };
  }

  // 0. Terminal Matching: uploading terminal must match the record's terminal_id
  if (terminalId !== uploadingTerminalId) {
    return {
      ok: false,
      status: "REJECTED",
      event_id: eventId,
      matric_number: matric,
      reason: `TERMINAL_MISMATCH: Record terminal ${terminalId} does not match uploading terminal ${uploadingTerminalId}`,
    };
  }

  // 1. Idempotency & Conflict Check: detect existing event_id
  const { data: existingLog, error: existErr } = await supabase
    .from("attendance_logs")
    .select("id, student_id, terminal_id, method, submission_digest")
    .eq("event_id", eventId)
    .maybeSingle();

  if (existErr) {
    return { ok: false, status: "RETRYABLE", event_id: eventId, matric_number: matric, reason: existErr.message };
  }

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
        status: "REJECTED",
        event_id: eventId,
        matric_number: matric,
        reason: `EVENT_ID_CONFLICT: Duplicate event_id ${eventId} submitted with conflicting student or terminal data`,
      };
    }
    return { ok: true, status: "DUPLICATE", event_id: eventId, matric_number: matric };
  }

  // 2. Look up student profile
  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id, matric_number")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr || !student) {
    return {
      ok: false,
      status: "REJECTED",
      event_id: eventId,
      matric_number: matric,
      reason: `No student profile found for matric ${matric}`,
    };
  }

  // 3. Cryptographic Verification
  let isStudentSigVerified = false;
  let isTerminalReceiptVerified = false;
  let matchedDevice: any = null;

  // 3a. If student signature and public key are present, verify student signature
  if (signature && publicKey) {
    const { data: dev, error: devErr } = await supabase
      .from("student_devices")
      .select("id, device_public_key, algorithm, enrolled_at, revoked_at")
      .eq("student_id", student.id)
      .eq("device_public_key", publicKey)
      .order("enrolled_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (devErr) {
      return { ok: false, status: "RETRYABLE", event_id: eventId, matric_number: matric, reason: devErr.message };
    }

    if (!dev) {
      return {
        ok: false,
        status: "REJECTED",
        event_id: eventId,
        matric_number: matric,
        reason: `UNENROLLED_DEVICE_KEY: Key not enrolled for student ${matric}`,
      };
    }
    matchedDevice = dev;

    const canonicalMessage = [
      "v1",
      "submission",
      eventId,
      credentialId,
      credentialVersion,
      matchedDevice.algorithm || "ECDSA_P256_SHA256",
      student.id,
      matric,
      terminalId,
      sessionId || "",
      challenge,
      timestamp.toString(),
      timestampSource,
    ].join("|");

    isStudentSigVerified = await verifyP256Signature(canonicalMessage, signature, publicKey);
    if (!isStudentSigVerified) {
      return {
        ok: false,
        status: "REJECTED",
        event_id: eventId,
        matric_number: matric,
        reason: `INVALID_SIGNATURE: Student ECDSA P-256 signature verification failed for ${matric}`,
      };
    }
  }

  // 3b. If terminal receipt signature is present, verify against uploading terminal public key
  if (termReceiptSig && uploadingTerminal.public_key && raw.terminal_saved_at) {
    const digestToVerify = submissionDigest || (signature && publicKey ? await sha256Hex([
      "v1", "submission", eventId, credentialId, credentialVersion,
      matchedDevice?.algorithm || "ECDSA_P256_SHA256", student.id, matric, terminalId,
      sessionId || "", challenge, timestamp.toString(), timestampSource
    ].join("|")) : "");

    const canonicalReceipt = [
      "v1",
      "receipt",
      eventId,
      terminalId,
      sessionId || "",
      digestToVerify,
      "DURABLY_SAVED",
      "true",
      raw.record_index?.trim() || "",
      raw.terminal_saved_at.trim(),
    ].join("|");

    isTerminalReceiptVerified = await verifyP256Signature(
      canonicalReceipt,
      termReceiptSig,
      uploadingTerminal.public_key,
    );

    if (!isTerminalReceiptVerified && !isStudentSigVerified) {
      return {
        ok: false,
        status: "REJECTED",
        event_id: eventId,
        matric_number: matric,
        reason: `INVALID_TERMINAL_RECEIPT: Terminal signature verification failed for receipt ${eventId}`,
      };
    }
  }

  // At least one valid cryptographic signature required
  if (!isStudentSigVerified && !isTerminalReceiptVerified) {
    return {
      ok: false,
      status: "REJECTED",
      event_id: eventId,
      matric_number: matric,
      reason: "MISSING_CRYPTOGRAPHIC_PROOF: Record lacks valid student signature or terminal receipt signature",
    };
  }

  // 4. Policy: Delayed records from subsequently revoked devices
  if (matchedDevice?.revoked_at) {
    if (timestampSource === "phone_os" || !raw.terminal_saved_at || !isTerminalReceiptVerified) {
      return {
        ok: false,
        status: "REJECTED",
        event_id: eventId,
        matric_number: matric,
        reason: "DEVICE_REVOKED_PRIOR_TO_SYNC: Device revoked before upload; provisional phone time cannot be trusted without verified terminal receipt",
      };
    }
    const termTime = new Date(raw.terminal_saved_at).getTime();
    const revokedTime = new Date(matchedDevice.revoked_at).getTime();
    if (isNaN(termTime) || termTime >= revokedTime) {
      return {
        ok: false,
        status: "REJECTED",
        event_id: eventId,
        matric_number: matric,
        reason: "DEVICE_REVOKED_BEFORE_RECORDING: Authenticated terminal timestamp indicates check-in occurred after device revocation",
      };
    }
  }

  // 5. Timestamps
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
  const verifiedAt = terminalSavedAt || phoneTime || new Date().toISOString();
  const { error: insertErr } = await supabase.from("attendance_logs").insert({
    session_id: sessionId,
    student_id: student.id,
    method: "ble_offline_signed",
    event_id: eventId,
    terminal_id: terminalId,
    terminal_saved_at: terminalSavedAt,
    phone_attendance_time: phoneTime,
    timestamp_source: timestampSource,
    terminal_receipt_sig: termReceiptSig || null,
    submission_digest: submissionDigest || null,
    offline_verified: true,
    verified_at: verifiedAt,
  });

  if (insertErr) {
    if (insertErr.code === "23505") {
      return { ok: true, status: "DUPLICATE", event_id: eventId, matric_number: matric };
    }
    return {
      ok: false,
      status: "RETRYABLE",
      event_id: eventId,
      matric_number: matric,
      reason: `Insert failed for ${matric}: ${insertErr.message}`,
    };
  }

  return { ok: true, status: "ACCEPTED", event_id: eventId, matric_number: matric };
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
    return { ok: false, status: "REJECTED", reason: "Empty matric number in attendance row" };
  }

  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr || !student) {
    return { ok: false, status: "REJECTED", matric_number: matric, reason: `No student profile found for matric ${matric}` };
  }

  const loggingType = (raw.logging_type ?? "").trim().toUpperCase();
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
    return {
      ok: false,
      status: "RETRYABLE",
      matric_number: matric,
      reason: `Failed to insert legacy attendance log for ${matric}: ${insertErr.message}`,
    };
  }

  return { ok: true, status: "ACCEPTED", matric_number: matric };
}

/**
 * Process a single enrollment CSV row.
 * CSV columns: Time, Name, Matric Number, RFID, Fingerprint ID
 */
async function processEnrollmentRow(
  supabase: SupabaseClient,
  raw: Record<string, string>,
): Promise<ProcessResult> {
  const matric = raw.matric_number?.trim();
  if (!matric) {
    return { ok: false, status: "REJECTED", reason: "Empty matric number in enrollment row" };
  }

  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr || !student) {
    return { ok: false, status: "REJECTED", matric_number: matric, reason: `No student profile found for matric ${matric}` };
  }

  const rfidCardId = raw.rfid?.trim() || null;
  const fingerprintId = raw.fingerprint_id ? parseInt(raw.fingerprint_id.trim(), 10) : null;

  const { data: existing, error: fetchErr } = await supabase
    .from("student_credentials")
    .select("id, rfid_card_id, fingerprint_id")
    .eq("student_id", student.id)
    .maybeSingle();

  if (fetchErr) {
    return { ok: false, status: "RETRYABLE", matric_number: matric, reason: `DB error: ${fetchErr.message}` };
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
      return { ok: false, status: "RETRYABLE", matric_number: matric, reason: `Update failed: ${updateErr.message}` };
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
      return { ok: false, status: "RETRYABLE", matric_number: matric, reason: `Insert failed: ${insertErr.message}` };
    }
  }

  return { ok: true, status: "ACCEPTED", matric_number: matric };
}

// ─── Main Handler ────────────────────────────────────────────────────────────

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  // Helper to fetch enrolled keys for terminal provisioning
  const fetchEnrolledKeys = async () => {
    const { data: activeStudentDevices } = await supabase
      .from("student_devices")
      .select("student_id, device_public_key, credential_id, algorithm, profiles!inner(matric_number, full_name)")
      .is("revoked_at", null);

    return (activeStudentDevices || []).map((d: any) => ({
      student_id: d.student_id,
      matric_number: d.profiles?.matric_number || "",
      public_key: d.device_public_key,
      credential_id: d.credential_id,
      algorithm: d.algorithm || "ECDSA_P256_SHA256",
    }));
  };

  const deviceKey = req.headers.get("x-device-key");
  const fileType = req.headers.get("x-sync-file-type");
  const syncAction = req.headers.get("x-sync-action")?.trim().toLowerCase();

  // Read request body
  let rawBodyText = "";
  let jsonBody: any = null;
  try {
    rawBodyText = await req.text();
    if (rawBodyText.trim().startsWith("{") || rawBodyText.trim().startsWith("[")) {
      jsonBody = JSON.parse(rawBodyText);
    }
  } catch {
    // If not JSON, rawBodyText remains
  }

  // ══════════════════════════════════════════════════════════════════════════
  // BRANCH 1: Mobile Admin BLE Sync Bridge ({ action: 'sync_attendance_batch' })
  // ══════════════════════════════════════════════════════════════════════════
  if (jsonBody && (jsonBody.action === "sync_attendance_batch" || jsonBody.action === "get_enrolled_keys")) {
    const adminToken = jsonBody.admin_token;
    if (!adminToken) {
      return json({ error: "Unauthorized: admin_token required for mobile admin sync bridge" }, 401);
    }

    // Verify admin/manager session
    const { data: sess, error: sessErr } = await supabase
      .from("active_sessions")
      .select("account_id, expires_at")
      .eq("token", adminToken)
      .gt("expires_at", new Date().toISOString())
      .maybeSingle();

    if (sessErr || !sess) {
      return json({ error: "Unauthorized: Invalid or expired admin session token" }, 401);
    }

    const { data: adminUser, error: adminErr } = await supabase
      .from("profiles")
      .select("id, role")
      .eq("id", sess.account_id)
      .maybeSingle();

    if (adminErr || !adminUser || (adminUser.role !== "administrator" && adminUser.role !== "manager")) {
      return json({ error: "Forbidden: Administrator or manager role required" }, 403);
    }

    // Action: get_enrolled_keys
    if (jsonBody.action === "get_enrolled_keys") {
      const keys = await fetchEnrolledKeys();
      return json({ ok: true, enrolled_keys: keys });
    }

    // Action: sync_attendance_batch
    const terminalId = jsonBody.terminal_id || "TERM-DEFAULT";
    const { data: terminalDevice } = await supabase
      .from("devices")
      .select("id, device_id, public_key, algorithm, is_active")
      .eq("device_id", terminalId)
      .maybeSingle();

    const effectiveTerminal = terminalDevice || {
      id: "00000000-0000-0000-0000-000000000000",
      device_id: terminalId,
      public_key: null,
      algorithm: "ECDSA_P256_SHA256",
    };

    const records = Array.isArray(jsonBody.records) ? jsonBody.records : [];
    let rowsAccepted = 0;
    let rowsDuplicates = 0;
    let rowsRejected = 0;
    let rowsRetryable = 0;
    const recordOutcomes: any[] = [];

    for (const r of records) {
      const rowRecord: Record<string, string> = {
        event_id: r.event_id || r.eventId || "",
        student_id: r.student_id || r.studentId || "",
        matric_number: r.matric_number || r.matricNumber || "",
        terminal_id: r.terminal_id || r.terminalId || terminalId,
        session_id: r.session_id || r.sessionId || "",
        timestamp: String(r.timestamp || 0),
        submission_digest: r.submission_digest || r.submissionDigest || "",
        terminal_receipt_signature: r.terminal_receipt_signature || r.terminalReceiptSignature || "",
        terminal_saved_at: r.terminal_saved_at || r.saved_at || r.savedAt || "",
        public_key: r.public_key || r.publicKey || "",
        signature: r.signature || "",
        challenge: r.challenge || "",
      };

      const result = await processSignedAttendanceRow(supabase, rowRecord, effectiveTerminal);
      if (result.status === "ACCEPTED") rowsAccepted++;
      else if (result.status === "DUPLICATE") rowsDuplicates++;
      else if (result.status === "RETRYABLE") rowsRetryable++;
      else rowsRejected++;

      recordOutcomes.push({
        event_id: result.event_id || rowRecord.event_id,
        matric_number: result.matric_number || rowRecord.matric_number,
        status: result.status,
        reason: result.reason,
      });
    }

    // Update terminal last_sync_at if terminal exists in DB
    if (terminalDevice) {
      await supabase
        .from("devices")
        .update({ last_sync_at: new Date().toISOString() })
        .eq("id", terminalDevice.id);
    }

    const enrolledKeys = await fetchEnrolledKeys();

    return json({
      ok: true,
      accepted: rowsAccepted,
      duplicate: rowsDuplicates,
      duplicates: rowsDuplicates,
      rejected: rowsRejected,
      retryable: rowsRetryable,
      rows_received: records.length,
      records: recordOutcomes,
      enrolled_keys: enrolledKeys,
    });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // BRANCH 2: Direct Hardware Terminal Upload (via x-device-key)
  // ══════════════════════════════════════════════════════════════════════════
  if (!deviceKey) {
    return json({
      error: "Unauthorized: Missing authentication (expected x-device-key header or valid admin_token in body)",
    }, 401);
  }

  // Authenticate terminal device via SHA-256 key hash
  const keyHash = await sha256Hex(deviceKey);
  const { data: device, error: deviceErr } = await supabase
    .from("devices")
    .select("id, device_id, public_key, algorithm, is_active")
    .eq("device_key_hash", keyHash)
    .maybeSingle();

  if (deviceErr || !device) {
    return json({ error: "Unauthorized — terminal key not recognized" }, 401);
  }

  if (device.is_active === false) {
    return json({ error: "Forbidden — terminal device is deactivated" }, 403);
  }

  // Direct Terminal Action: Refresh Credentials
  if (syncAction === "refresh_credentials" || !rawBodyText.trim()) {
    const enrolledKeys = await fetchEnrolledKeys();
    return json({
      accepted: 0,
      duplicates: 0,
      rejected: 0,
      retryable: 0,
      rows_received: 0,
      records: [],
      enrolled_keys: enrolledKeys,
    });
  }

  if (!fileType || (fileType !== "attendance" && fileType !== "enrollment" && fileType !== "signed_attendance")) {
    return json({
      error: "Missing or invalid x-sync-file-type header (expected 'attendance', 'enrollment', or 'signed_attendance')",
    }, 400);
  }

  let rowsReceived = 0;
  let rowsAccepted = 0;
  let rowsDuplicates = 0;
  let rowsRejected = 0;
  let rowsRetryable = 0;
  const recordOutcomes: any[] = [];

  // Signed attendance records (JSON array or CSV)
  if (jsonBody || fileType === "signed_attendance") {
    let records: Record<string, string>[] = [];
    if (jsonBody) {
      records = Array.isArray(jsonBody) ? jsonBody : [jsonBody];
    } else {
      const lines = rawBodyText.trim().split(/\r?\n/).filter((l) => l.trim().length > 0);
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
          timestamp_source: c[10] ?? "phone_os",
          credential_id: c[11] ?? "",
          credential_version: c[12] ?? "v1",
          algorithm: c[13] ?? "ECDSA_P256_SHA256",
          submission_digest: c[14] ?? "",
          terminal_receipt_signature: c[15] ?? "",
        };
      });
    }

    rowsReceived = records.length;
    for (const record of records) {
      const result = await processSignedAttendanceRow(supabase, record, device);
      if (result.status === "ACCEPTED") rowsAccepted++;
      else if (result.status === "DUPLICATE") rowsDuplicates++;
      else if (result.status === "RETRYABLE") rowsRetryable++;
      else rowsRejected++;

      recordOutcomes.push({
        event_id: result.event_id || record.event_id,
        matric_number: result.matric_number || record.matric_number,
        status: result.status,
        reason: result.reason,
      });
    }
  } else {
    // Legacy CSV processing
    const allLines = rawBodyText.trim().split(/\r?\n/).filter((l) => l.trim().length > 0);
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

      if (result.status === "ACCEPTED") rowsAccepted++;
      else if (result.status === "DUPLICATE") rowsDuplicates++;
      else if (result.status === "RETRYABLE") rowsRetryable++;
      else rowsRejected++;

      recordOutcomes.push({
        matric_number: result.matric_number || rawRow.matric_number,
        status: result.status,
        reason: result.reason,
      });
    }
  }

  // Update terminal last_sync_at
  await supabase
    .from("devices")
    .update({ last_sync_at: new Date().toISOString() })
    .eq("id", device.id);

  const enrolledKeys = await fetchEnrolledKeys();

  return json({
    accepted: rowsAccepted,
    duplicate: rowsDuplicates,
    duplicates: rowsDuplicates,
    rejected: rowsRejected,
    retryable: rowsRetryable,
    rows_received: rowsReceived,
    records: recordOutcomes,
    enrolled_keys: enrolledKeys,
  });
});
