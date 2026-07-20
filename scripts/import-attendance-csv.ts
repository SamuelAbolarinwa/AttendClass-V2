import "dotenv/config";
import fs from "fs";
import { createClient } from "@supabase/supabase-js";
import WebSocket from "ws";

const SUPABASE_URL = process.env.VITE_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.VITE_SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error("Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
  realtime: { transport: WebSocket }
});

async function main() {
  const csvPath = process.argv[2] || "/home/abolarinwa-sa/Documents/New Attendance SYS/AEIRG_Attendance_Register_2026-07-20.csv";
  const overridesArg = process.argv[3];
  
  let overrides: Record<string, string> = {};
  if (overridesArg) {
    try {
      overrides = JSON.parse(overridesArg);
    } catch (e) {
      console.error("Failed to parse JSON overrides:", e);
      process.exit(1);
    }
  }

  console.log(`Reading CSV: ${csvPath}`);
  const csvText = fs.readFileSync(csvPath, "utf-8");
  const lines = csvText.trim().split(/\r?\n/);
  
  if (lines.length < 2) {
    console.error("CSV is empty or missing data.");
    process.exit(1);
  }

  // Parse headers
  const headers = lines[0].split(",").map(h => h.trim());
  const dateColumns: { index: number; dateStr: string; isHoliday: boolean }[] = [];
  
  for (let i = 3; i < headers.length; i++) {
    const h = headers[i];
    if (h === "Days Present" || h === "Days Absent" || h === "Attendance %") continue;
    
    // Format: "YYYY-MM-DD" or "YYYY-MM-DD (HOLIDAY)"
    const match = h.match(/^(\d{4}-\d{2}-\d{2})/);
    if (match) {
      dateColumns.push({
        index: i,
        dateStr: match[1],
        isHoliday: h.includes("(HOLIDAY)")
      });
    }
  }

  console.log(`Found ${dateColumns.length} date columns (${dateColumns.filter(d => d.isHoliday).length} holidays).`);

  // Step 1: Upsert Cancelled Days
  const holidayDates = dateColumns.filter(d => d.isHoliday).map(d => d.dateStr);
  let holidaysUpserted = 0;
  
  if (holidayDates.length > 0) {
    const { error: holErr } = await supabase.from("cancelled_days").upsert(
      holidayDates.map(d => ({ cancelled_date: d, reason: "Imported from legacy register" })),
      { onConflict: "cancelled_date" }
    );
    if (holErr) throw new Error(`Failed to upsert cancelled days: ${holErr.message}`);
    holidaysUpserted = holidayDates.length;
  }

  // Step 2: Login as admin to use platform_admin RPC for user creation
  const { data: loginData, error: loginErr } = await supabase.rpc("platform_login", {
    p_identifier: "admin@attendclass.local",
    p_password: "Samuel@10"
  });

  if (loginErr || !(loginData as any)?.ok) {
    console.error("Failed to login as admin. Did you set the password to something else?", loginErr?.message || (loginData as any)?.error);
    process.exit(1);
  }
  const adminToken = (loginData as any).token;

  // Step 3: Parse students and create missing ones
  const students = [];
  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split(",");
    if (parts.length < 3) continue;
    const name = parts[1].trim();
    const matric = parts[2].trim();
    if (!name || !matric) continue;
    
    students.push({
      name,
      identifier: matric,
      role: "user",
      rowParts: parts
    });
  }

  console.log(`Found ${students.length} students in CSV. Ensuring profiles exist...`);
  const { data: adminData, error: adminErr } = await supabase.rpc("platform_admin", {
    p_token: adminToken,
    p_op: "addUsers",
    p_args: { users: students.map(s => ({ name: s.name, identifier: s.identifier, role: s.role })) }
  });

  if (adminErr || !(adminData as any)?.ok) {
    throw new Error(`Failed to create students: ${adminErr?.message || (adminData as any)?.error}`);
  }

  const createdCount = (adminData as any).created?.length || 0;
  const matchedCount = students.length - createdCount;
  console.log(`Created ${createdCount} new students, matched ${matchedCount} existing.`);

  // Fetch all profile IDs for these matric numbers
  const matrics = students.map(s => s.identifier);
  const { data: profiles, error: profErr } = await supabase
    .from("profiles")
    .select("id, identifier")
    .in("identifier", matrics);
    
  if (profErr) throw new Error(`Failed to fetch profiles: ${profErr.message}`);
  
  const profileMap = new Map(profiles.map(p => [p.identifier, p.id]));

  // Step 4: Apply tracking_start_date overrides
  if (Object.keys(overrides).length > 0) {
    console.log(`Applying ${Object.keys(overrides).length} tracking_start_date override(s)...`);
    for (const [matric, startDate] of Object.entries(overrides)) {
      const pid = profileMap.get(matric);
      if (pid) {
        const { error: updErr } = await supabase.from("profiles")
          .update({ tracking_start_date: startDate })
          .eq("id", pid);
        if (updErr) console.error(`Failed to update override for ${matric}:`, updErr.message);
        else console.log(`✓ Overrode tracking_start_date for ${matric} -> ${startDate}`);
      } else {
        console.warn(`Override specified for ${matric} but profile not found.`);
      }
    }
  }

  // Step 5: Gather attendance records to insert
  // We need to avoid duplicates. We'll fetch all existing legacy_import logs for these students.
  const { data: existingLogs, error: logErr } = await supabase
    .from("attendance_logs")
    .select("student_id, verified_at")
    .eq("method", "legacy_import");

  if (logErr) throw new Error(`Failed to fetch existing logs: ${logErr.message}`);

  const existingSet = new Set(
    existingLogs.map(l => `${l.student_id}_${new Date(l.verified_at).toISOString().split('T')[0]}`)
  );

  const logsToInsert = [];
  let duplicateSkips = 0;

  for (const student of students) {
    const pid = profileMap.get(student.identifier);
    if (!pid) continue;

    for (const col of dateColumns) {
      if (col.isHoliday) continue;
      
      const val = student.rowParts[col.index]?.trim();
      if (val === "✓") {
        const dateStr = col.dateStr; // YYYY-MM-DD
        const key = `${pid}_${dateStr}`;
        if (existingSet.has(key)) {
          duplicateSkips++;
        } else {
          logsToInsert.push({
            student_id: pid,
            method: "legacy_import",
            verified_at: `${dateStr}T08:00:00Z` // Fixed time 08:00 UTC
          });
          existingSet.add(key); // prevent duplicates within the same run if any
        }
      }
    }
  }

  // Insert in batches of 500
  let insertedLogs = 0;
  const BATCH_SIZE = 500;
  console.log(`Ready to insert ${logsToInsert.length} new attendance logs (skipped ${duplicateSkips} existing).`);

  for (let i = 0; i < logsToInsert.length; i += BATCH_SIZE) {
    const batch = logsToInsert.slice(i, i + BATCH_SIZE);
    const { error: insErr } = await supabase.from("attendance_logs").insert(batch);
    if (insErr) {
      console.error(`Failed to insert batch ${i}:`, insErr.message);
    } else {
      insertedLogs += batch.length;
    }
  }

  // Final summary
  console.log("\n" + "=".repeat(40));
  console.log("IMPORT SUMMARY");
  console.log("=".repeat(40));
  console.log(`Students processed:       ${students.length}`);
  console.log(`  - New profiles created: ${createdCount}`);
  console.log(`  - Existing matched:     ${matchedCount}`);
  console.log(`Cancelled days upserted:  ${holidaysUpserted}`);
  console.log(`Attendance logs inserted: ${insertedLogs}`);
  console.log(`Attendance logs skipped:  ${duplicateSkips} (already existed)`);
  
  if (overrides["BU23MCT1014"]) {
    console.log(`Confirmed Folorunsho Promise tracking_start_date set to ${overrides["BU23MCT1014"]}`);
  }
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
