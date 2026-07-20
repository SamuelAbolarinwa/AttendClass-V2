/**
 * hardware-sync — Supabase Edge Function
 *
 * Drop-in cloud replacement for the ESP32 firmware's CSV upload endpoint.
 * Accepts raw CSV via POST, authenticates the device by x-device-key,
 * inserts every row into hardware_sync_log for audit, then attempts to
 * process each row into the normalised tables (attendance_logs or
 * student_credentials).
 *
 * CONTRACT (firmware sends exactly this — do NOT change):
 *   POST /hardware-sync
 *   Content-Type: text/csv
 *   x-sync-file-type: "attendance" | "enrollment"
 *   x-device-key: <static per-device secret>
 *   Body: raw CSV text
 */

import { createClient, SupabaseClient } from "jsr:@supabase/supabase-js@2";

// ─── Helpers ────────────────────────────────────────────────────────────────

/** SHA-256 hex digest — used to compare x-device-key against devices.device_key_hash */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Trim surrounding quotes from a CSV field (handles Excel-style quoting). */
function unquote(field: string): string {
  const trimmed = field.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/""/g, '"');
  }
  return trimmed;
}

/** Simple CSV line splitter (no embedded commas expected from ESP32). */
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

// ─── Row processors ─────────────────────────────────────────────────────────

interface ProcessResult {
  ok: boolean;
  warning?: string;
}

/**
 * Process a single attendance CSV row.
 *
 * CSV columns: Time, Name, Matric Number, Logging Type
 * Maps to attendance_logs with session_id = NULL (legacy import).
 */
async function processAttendanceRow(
  supabase: SupabaseClient,
  raw: Record<string, string>,
): Promise<ProcessResult> {
  const matric = raw.matric_number;
  if (!matric) {
    return { ok: false, warning: "Empty matric number in attendance row" };
  }

  // Look up student profile by matric number
  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr) {
    return { ok: false, warning: `DB error looking up matric ${matric}: ${studentErr.message}` };
  }
  if (!student) {
    return { ok: false, warning: `No student profile found for matric ${matric}` };
  }

  // Determine attendance method from the "Logging Type" column
  const loggingType = (raw.logging_type ?? "").trim().toUpperCase();
  const method: string =
    loggingType === "QR_BLE" ? "qr_ble_legacy" : "2fa_rfid_fp";

  // Parse the timestamp from the ESP32 (format varies; fall back to now())
  let verifiedAt: string;
  try {
    const parsed = new Date(raw.time);
    verifiedAt = isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
  } catch {
    verifiedAt = new Date().toISOString();
  }

  const { error: insertErr } = await supabase.from("attendance_logs").insert({
    session_id: null, // legacy CSV imports have no session context
    student_id: student.id,
    method,
    verified_at: verifiedAt,
  });

  if (insertErr) {
    return { ok: false, warning: `Failed to insert attendance log for ${matric}: ${insertErr.message}` };
  }

  return { ok: true };
}

/**
 * Process a single enrollment CSV row.
 *
 * CSV columns: Time, Name, Matric Number, RFID, Fingerprint ID
 * Upserts into student_credentials.
 */
async function processEnrollmentRow(
  supabase: SupabaseClient,
  raw: Record<string, string>,
): Promise<ProcessResult> {
  const matric = raw.matric_number;
  if (!matric) {
    return { ok: false, warning: "Empty matric number in enrollment row" };
  }

  const { data: student, error: studentErr } = await supabase
    .from("profiles")
    .select("id")
    .eq("matric_number", matric)
    .maybeSingle();

  if (studentErr) {
    return { ok: false, warning: `DB error looking up matric ${matric}: ${studentErr.message}` };
  }
  if (!student) {
    return { ok: false, warning: `No student profile found for matric ${matric}` };
  }

  const rfidCardId = raw.rfid?.trim() || null;
  const rawFpId = raw.fingerprint_id?.trim();
  const fingerprintId = rawFpId ? parseInt(rawFpId, 10) : null;

  // Check for existing credential row for this student
  const { data: existing, error: fetchErr } = await supabase
    .from("student_credentials")
    .select("id, rfid_card_id, fingerprint_id")
    .eq("student_id", student.id)
    .maybeSingle();

  if (fetchErr) {
    return { ok: false, warning: `DB error fetching credentials for ${matric}: ${fetchErr.message}` };
  }

  if (existing) {
    // Update only the fields that are actually provided (non-null), preserving existing values
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (rfidCardId !== null) updates.rfid_card_id = rfidCardId;
    if (fingerprintId !== null) updates.fingerprint_id = fingerprintId;

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
        fingerprint_id: fingerprintId,
      });

    if (insertErr) {
      return { ok: false, warning: `Failed to insert credentials for ${matric}: ${insertErr.message}` };
    }
  }

  return { ok: true };
}

// ─── Main handler ────────────────────────────────────────────────────────────

Deno.serve(async (req: Request): Promise<Response> => {
  // ── Method gate ──────────────────────────────────────────────────────────
  if (req.method === "OPTIONS") {
    // CORS preflight (not needed by ESP32 but useful for curl / Postman)
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

  // ── Read & validate headers ──────────────────────────────────────────────
  const fileType = req.headers.get("x-sync-file-type");
  const deviceKey = req.headers.get("x-device-key");

  if (!deviceKey) {
    return json({ error: "Missing x-device-key header" }, 401);
  }
  if (!fileType || (fileType !== "attendance" && fileType !== "enrollment")) {
    return json({ error: "Missing or invalid x-sync-file-type header (expected 'attendance' or 'enrollment')" }, 400);
  }

  // ── Authenticate device ──────────────────────────────────────────────────
  // Hash the incoming key with SHA-256 and look it up directly in the DB.
  // When registering devices, store SHA-256 hex digest in devices.device_key_hash.
  const keyHash = await sha256Hex(deviceKey);

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, // bypass RLS — server-to-server
  );

  const { data: device, error: deviceErr } = await supabase
    .from("devices")
    .select("id, device_id")
    .eq("device_key_hash", keyHash)
    .maybeSingle();

  if (deviceErr || !device) {
    console.error("Device auth failed:", deviceErr?.message ?? "no matching device_key_hash");
    return json({ error: "Unauthorized — device key not recognised" }, 401);
  }

  console.log(`Authenticated device ${device.device_id} (${device.id})`);

  // ── Read body ────────────────────────────────────────────────────────────
  let body: string;
  try {
    body = await req.text();
  } catch {
    return json({ error: "Failed to read request body" }, 400);
  }

  if (!body.trim()) {
    return json({ error: "Empty CSV body" }, 400);
  }

  // ── Parse CSV lines ──────────────────────────────────────────────────────
  const allLines = body.trim().split(/\r?\n/).filter((l) => l.trim().length > 0);

  // Detect and skip header row if present
  const HEADER_RE = /^\s*time\s*,\s*name\s*,\s*matric/i;
  const dataLines = allLines.length > 0 && HEADER_RE.test(allLines[0])
    ? allLines.slice(1)
    : allLines;

  const rowsReceived = dataLines.length;
  let rowsProcessed = 0;
  let rowsFailed = 0;
  const warnings: string[] = [];

  // ── Process each row ─────────────────────────────────────────────────────
  for (const line of dataLines) {
    const cols = splitCSVLine(line);

    // Build the raw JSON object (column names normalised to snake_case)
    let rawRow: Record<string, string>;

    if (fileType === "attendance") {
      // Expected: Time, Name, Matric Number, Logging Type
      rawRow = {
        time: cols[0] ?? "",
        name: cols[1] ?? "",
        matric_number: cols[2] ?? "",
        logging_type: cols[3] ?? "",
      };
    } else {
      // Expected: Time, Name, Matric Number, RFID, Fingerprint ID
      rawRow = {
        time: cols[0] ?? "",
        name: cols[1] ?? "",
        matric_number: cols[2] ?? "",
        rfid: cols[3] ?? "",
        fingerprint_id: cols[4] ?? "",
      };
    }

    // ── Step 1: Always insert into hardware_sync_log (audit trail) ───────
    const { data: syncRow, error: syncErr } = await supabase
      .from("hardware_sync_log")
      .insert({
        device_id: device.id,
        file_type: fileType,
        raw_row: rawRow,
        processed: false,
      })
      .select("id")
      .single();

    if (syncErr) {
      // If we can't even write the audit row, count it as failed but keep going
      console.error("Failed to insert hardware_sync_log row:", syncErr.message);
      rowsFailed++;
      continue;
    }

    // ── Step 2: Attempt to process into normalised tables ────────────────
    const result: ProcessResult =
      fileType === "attendance"
        ? await processAttendanceRow(supabase, rawRow)
        : await processEnrollmentRow(supabase, rawRow);

    if (result.ok) {
      // ── Step 3: Mark audit row as processed ───────────────────────────
      const { error: updateErr } = await supabase
        .from("hardware_sync_log")
        .update({ processed: true })
        .eq("id", syncRow.id);

      if (updateErr) {
        console.warn(`Processed row but failed to mark sync log ${syncRow.id}:`, updateErr.message);
      }

      rowsProcessed++;
    } else {
      console.warn(`Row processing warning: ${result.warning}`);
      warnings.push(result.warning ?? "unknown error");
      rowsFailed++;
    }
  }

  // ── Return summary ───────────────────────────────────────────────────────
  console.log(
    `Sync complete for ${device.device_id}: ${rowsReceived} received, ${rowsProcessed} processed, ${rowsFailed} failed`,
  );

  return json({
    rows_received: rowsReceived,
    rows_processed: rowsProcessed,
    rows_failed: rowsFailed,
    // Include warnings only if there are any (helpful for debugging, firmware ignores them)
    ...(warnings.length > 0 ? { warnings } : {}),
  });
});
