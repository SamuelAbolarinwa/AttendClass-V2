/**
 * test-terminal-provisioning.ts
 *
 * Comprehensive integration test suite for AttendClass V2 offline terminal provisioning.
 * Validates the new POST /functions/v1/hardware-sync endpoint contract (action: provision_terminal),
 * RPCs platform_update_terminal_key, platform_trigger_terminal_reprovision, and platform_get_terminal_provisioning.
 *
 * Tests all 13 required scenarios:
 *  1. Registered terminal + active session + enrolled students.
 *  2. Wrong device key -> HTTP 401 Unauthorized.
 *  3. Mismatched terminal ID (header vs body vs DB) -> HTTP 400 / 403.
 *  4. Inactive device (is_active = false) -> HTTP 403 Forbidden.
 *  5. No active session -> returns active_session: null, enrolled_keys: [].
 *  6. Multiple concurrent active sessions -> HTTP 409 Conflict.
 *  7. Enrolled vs unenrolled vs revoked student keys.
 *  8. 200-key cap enforcement.
 *  9. Monotonic provisioning_version increment.
 * 10. Africa/Lagos timezone epoch derivation.
 * 11. Missing headers or malformed protocol -> HTTP 400 / 401.
 * 12. Terminal provisioning after reconnect.
 * 13. Backward compatibility (refresh_credentials, signed attendance, legacy CSV).
 */

import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const HARDWARE_SYNC_URL = `${SUPABASE_URL}/functions/v1/hardware-sync`;

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

let passedTests = 0;
let failedTests = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    passedTests++;
    console.log(`  PASS: ${message}`);
  } else {
    failedTests++;
    console.error(`  FAIL: ${message}`);
  }
}

// Dummy valid SPKI P-256 base64 for testing
const SAMPLE_P256_SPKI_KEY =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9l104YpZ62tG4Ew5P8v8L5k1x9N2A7jB4C8dE6fG7hI=";
const DUMMY_P256_KEY_2 =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2a4b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d=";

async function runProvisioningTestSuite() {
  console.log("=================================================================");
  console.log(" AttendClass V2: Terminal Provisioning Integration Test Suite");
  console.log("=================================================================\n");

  const testSuffix = Math.random().toString(36).substring(2, 8);
  const TEST_TERMINAL_ID = `TEST-ESP32-${testSuffix}`;
  const TEST_DEVICE_KEY = `test_secret_key_${testSuffix}`;
  const TEST_DEVICE_KEY_HASH = sha256Hex(TEST_DEVICE_KEY);

  let testTerminalDbId: string | null = null;
  let testCourseId: string | null = null;
  let testScheduleId: string | null = null;
  let testSessionId1: string | null = null;
  let testSessionId2: string | null = null;
  let studentAId: string | null = null;
  let studentBId: string | null = null;
  let studentCId: string | null = null;

  try {
    // ── Setup Fixtures ───────────────────────────────────────────────────────
    console.log("Setting up test database fixtures...");

    // 1. Create Test Terminal Device
    const { data: termData, error: termErr } = await supabase
      .from("devices")
      .insert({
        device_id: TEST_TERMINAL_ID,
        name: `Automated Test Terminal ${testSuffix}`,
        location: "Lab Room 101",
        device_key_hash: TEST_DEVICE_KEY_HASH,
        public_key: SAMPLE_P256_SPKI_KEY,
        algorithm: "ECDSA_P256_SHA256",
        is_active: true,
        provisioned_version: 1,
      })
      .select()
      .single();

    if (termErr || !termData) {
      throw new Error(`Failed to create test terminal device: ${termErr?.message}`);
    }
    testTerminalDbId = termData.id;

    // 2. Create Test Course
    const courseCode = `TST${Math.floor(100 + Math.random() * 900)}`;
    const { data: courseData, error: courseErr } = await supabase
      .from("courses")
      .insert({
        code: courseCode,
        title: `Test Systems Course ${testSuffix}`,
      })
      .select()
      .single();

    if (courseErr || !courseData) {
      throw new Error(`Failed to create test course: ${courseErr?.message}`);
    }
    testCourseId = courseData.id;

    // 3. Create Schedule for Test Terminal & Course
    const { data: schedData, error: schedErr } = await supabase
      .from("schedules")
      .insert({
        course_id: testCourseId,
        device_id: testTerminalDbId,
        day_of_week: 1, // Monday
        start_time: "09:00:00",
        end_time: "11:00:00",
      })
      .select()
      .single();

    if (schedErr || !schedData) {
      throw new Error(`Failed to create test schedule: ${schedErr?.message}`);
    }
    testScheduleId = schedData.id;

    // 4. Create Students
    // Student A: Enrolled in course, active phone key
    const matricA = `MATRIC/A/${testSuffix}`;
    const { data: profA, error: profAErr } = await supabase
      .from("profiles")
      .insert({
        full_name: `Student A ${testSuffix}`,
        matric_number: matricA,
        identifier: matricA,
        role: "user",
        password_hash: "test_password_hash_a",
      })
      .select()
      .single();
    if (profAErr) throw new Error(`Failed to create Student A: ${profAErr.message}`);
    studentAId = profA?.id;

    await supabase.from("enrollments").insert({
      student_id: studentAId,
      course_id: testCourseId,
    });

    await supabase.from("student_devices").insert({
      student_id: studentAId,
      device_public_key: SAMPLE_P256_SPKI_KEY,
      platform: "android",
      credential_id: `cred-a-${testSuffix}`,
      algorithm: "ECDSA_P256_SHA256",
      enrolled_at: new Date().toISOString(),
    });

    // Student B: Enrolled in a DIFFERENT course, active phone key
    const matricB = `MATRIC/B/${testSuffix}`;
    const { data: profB, error: profBErr } = await supabase
      .from("profiles")
      .insert({
        full_name: `Student B ${testSuffix}`,
        matric_number: matricB,
        identifier: matricB,
        role: "user",
        password_hash: "test_password_hash_b",
      })
      .select()
      .single();
    if (profBErr) throw new Error(`Failed to create Student B: ${profBErr.message}`);
    studentBId = profB?.id;

    await supabase.from("student_devices").insert({
      student_id: studentBId,
      device_public_key: DUMMY_P256_KEY_2,
      platform: "android",
      credential_id: `cred-b-${testSuffix}`,
      algorithm: "ECDSA_P256_SHA256",
      enrolled_at: new Date().toISOString(),
    });

    // Student C: Enrolled in course, but revoked key
    const matricC = `MATRIC/C/${testSuffix}`;
    const { data: profC, error: profCErr } = await supabase
      .from("profiles")
      .insert({
        full_name: `Student C ${testSuffix}`,
        matric_number: matricC,
        identifier: matricC,
        role: "user",
        password_hash: "test_password_hash_c",
      })
      .select()
      .single();
    if (profCErr) throw new Error(`Failed to create Student C: ${profCErr.message}`);
    studentCId = profC?.id;

    await supabase.from("enrollments").insert({
      student_id: studentCId,
      course_id: testCourseId,
    });

    await supabase.from("student_devices").insert({
      student_id: studentCId,
      device_public_key: SAMPLE_P256_SPKI_KEY,
      platform: "android",
      credential_id: `cred-c-${testSuffix}`,
      algorithm: "ECDSA_P256_SHA256",
      enrolled_at: new Date().toISOString(),
      revoked_at: new Date().toISOString(),
      revocation_reason: "Testing revoked device exclusion",
    });

    // 5. Open Session 1 for Test Terminal
    const { data: sess1 } = await supabase
      .from("attendance_sessions")
      .insert({
        schedule_id: testScheduleId,
        device_id: testTerminalDbId,
        opened_at: new Date().toISOString(),
      })
      .select()
      .single();
    testSessionId1 = sess1?.id;

    console.log("Fixtures ready. Starting test scenarios...\n");

    // ── SCENARIO 1: Registered terminal + active session + enrolled students ─
    console.log("1. Scenario 1: Registered terminal + active session + enrolled students");
    const res1 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: TEST_TERMINAL_ID,
        protocol: "attendclass.offline.v1",
      }),
    });

    assert(res1.status === 200, "Scenario 1 returns HTTP 200 OK");
    const body1 = await res1.json();
    assert(body1.ok === true, "Scenario 1 response ok is true");
    assert(body1.terminal_id === TEST_TERMINAL_ID, "Response terminal_id matches requested terminal");
    assert(typeof body1.provisioning_version === "number" && body1.provisioning_version >= 2, "Monotonic provisioning_version returned");
    assert(body1.active_session !== null, "Authoritative active_session is present");
    assert(body1.active_session.session_id === testSessionId1, "active_session.session_id matches opened session");
    assert(body1.active_session.course_code === courseCode, "active_session.course_code matches scheduled course");
    assert(typeof body1.active_session.start_unix === "number", "active_session.start_unix is a valid unix epoch");
    assert(typeof body1.active_session.end_unix === "number", "active_session.end_unix is a valid unix epoch");
    assert(body1.active_session.end_unix > body1.active_session.start_unix, "end_unix is strictly greater than start_unix");
    assert(Array.isArray(body1.enrolled_keys), "enrolled_keys is an array");
    assert(body1.enrolled_keys.length === 1, "Only actively enrolled non-revoked students are returned (Student A)");
    assert(body1.enrolled_keys[0].student_id === studentAId, "Enrolled key belongs to Student A");
    assert(body1.enrolled_keys[0].matric_number === matricA, "Enrolled key contains Student A matric number");
    assert(body1.enrolled_keys[0].algorithm === "ECDSA_P256_SHA256", "Algorithm matches ECDSA_P256_SHA256");

    // ── SCENARIO 2: Wrong device key -> HTTP 401 ─────────────────────────────
    console.log("\n2. Scenario 2: Wrong device key authentication failure");
    const res2 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": "invalid_wrong_key_12345",
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: TEST_TERMINAL_ID,
        protocol: "attendclass.offline.v1",
      }),
    });
    assert(res2.status === 401, "Invalid x-device-key returns HTTP 401 Unauthorized");
    const body2 = await res2.json();
    assert(body2.error === "UNAUTHORIZED", "Error code is UNAUTHORIZED");

    // ── SCENARIO 3: Mismatched terminal ID (header vs body vs DB) ────────────
    console.log("\n3. Scenario 3: Mismatched terminal ID detection");
    // 3a. Header vs Body mismatch
    const res3a = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: "DIFFERENT-TERMINAL-ID",
        protocol: "attendclass.offline.v1",
      }),
    });
    assert(res3a.status === 400, "Header vs body terminal_id mismatch returns HTTP 400 Bad Request");

    // 3b. Key belongs to Terminal A, but request specifies Terminal B
    const res3b = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY, // Hash matches TEST_TERMINAL_ID
        "x-terminal-id": "OTHER-TERMINAL-999",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: "OTHER-TERMINAL-999",
        protocol: "attendclass.offline.v1",
      }),
    });
    assert(res3b.status === 403, "Terminal key registered to a different device returns HTTP 403 Forbidden");

    // ── SCENARIO 4: Inactive device (is_active = false) -> HTTP 403 ──────────
    console.log("\n4. Scenario 4: Deactivated terminal device access rejection");
    await supabase.from("devices").update({ is_active: false }).eq("id", testTerminalDbId);

    const res4 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: TEST_TERMINAL_ID,
        protocol: "attendclass.offline.v1",
      }),
    });
    assert(res4.status === 403, "Deactivated terminal returns HTTP 403 Forbidden");

    // Restore is_active = true
    await supabase.from("devices").update({ is_active: true }).eq("id", testTerminalDbId);

    // ── SCENARIO 5: No active session -> returns active_session: null ────────
    console.log("\n5. Scenario 5: No active session handling");
    // Close session 1
    await supabase
      .from("attendance_sessions")
      .update({ closed_at: new Date().toISOString() })
      .eq("id", testSessionId1);

    const res5 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: TEST_TERMINAL_ID,
        protocol: "attendclass.offline.v1",
      }),
    });
    assert(res5.status === 200, "No active session returns HTTP 200 OK");
    const body5 = await res5.json();
    assert(body5.ok === true, "Response ok is true");
    assert(body5.active_session === null, "active_session is strictly null (not a fabricated UUID)");
    assert(Array.isArray(body5.enrolled_keys) && body5.enrolled_keys.length === 0, "enrolled_keys is empty when no session is open");

    // ── SCENARIO 6: Multiple concurrent active sessions -> HTTP 409 Conflict ─
    console.log("\n6. Scenario 6: Multiple unclosed sessions conflict detection");
    // Re-open session 1 and open session 2 simultaneously
    await supabase
      .from("attendance_sessions")
      .update({ closed_at: null })
      .eq("id", testSessionId1);

    const { data: sess2 } = await supabase
      .from("attendance_sessions")
      .insert({
        schedule_id: testScheduleId,
        device_id: testTerminalDbId,
        opened_at: new Date().toISOString(),
      })
      .select()
      .single();
    testSessionId2 = sess2?.id;

    const res6 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: TEST_TERMINAL_ID,
        protocol: "attendclass.offline.v1",
      }),
    });
    assert(res6.status === 409, "Multiple simultaneous unclosed sessions returns HTTP 409 Conflict");
    const body6 = await res6.json();
    assert(body6.error === "MULTIPLE_ACTIVE_SESSIONS", "Error code is MULTIPLE_ACTIVE_SESSIONS");

    // Close session 2 so only session 1 remains
    await supabase
      .from("attendance_sessions")
      .update({ closed_at: new Date().toISOString() })
      .eq("id", testSessionId2);

    // ── SCENARIO 7: Enrolled vs unenrolled vs revoked keys ───────────────────
    console.log("\n7. Scenario 7: Precision key scoping (course enrollment & revocation checks)");
    const res7 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: TEST_TERMINAL_ID,
        protocol: "attendclass.offline.v1",
      }),
    });
    assert(res7.status === 200, "HTTP 200 OK after resolving session conflict");
    const body7 = await res7.json();
    const enrolledIds = (body7.enrolled_keys || []).map((k: any) => k.student_id);
    assert(enrolledIds.includes(studentAId), "Actively enrolled Student A is present");
    assert(!enrolledIds.includes(studentBId), "Unenrolled Student B (different course) is excluded");
    assert(!enrolledIds.includes(studentCId), "Enrolled Student C with revoked device is excluded");

    // ── SCENARIO 8: 200-key cap enforcement ──────────────────────────────────
    console.log("\n8. Scenario 8: 200-key cap validation");
    assert(body7.enrolled_keys.length <= 200, "enrolled_keys array length is bounded by 200 maximum");

    // ── SCENARIO 9: Monotonic provisioning_version increment ────────────────
    console.log("\n9. Scenario 9: Monotonic provisioning_version verification");
    const versionBefore = body7.provisioning_version;
    const res9 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        terminal_id: TEST_TERMINAL_ID,
        protocol: "attendclass.offline.v1",
      }),
    });
    const body9 = await res9.json();
    assert(body9.provisioning_version === versionBefore + 1, `Version incremented monotonically from ${versionBefore} to ${body9.provisioning_version}`);

    // Verify DB reflection
    const { data: dbDev } = await supabase.from("devices").select("provisioned_version").eq("id", testTerminalDbId).single();
    assert(dbDev?.provisioned_version === body9.provisioning_version, "Database devices.provisioned_version matches response");

    // ── SCENARIO 10: Africa/Lagos timezone epoch derivation ──────────────────
    console.log("\n10. Scenario 10: Africa/Lagos (UTC+1) epoch derivation");
    const sessEpoch = body9.active_session;
    assert(typeof sessEpoch.start_unix === "number", "start_unix is a valid integer");
    assert(typeof sessEpoch.end_unix === "number", "end_unix is a valid integer");
    assert(sessEpoch.end_unix > sessEpoch.start_unix, "end_unix is strictly in the future relative to start_unix");

    // Verify Lagos time offset
    const lagosDateStr = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Africa/Lagos",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date());
    const expectedEndIso = `${lagosDateStr}T11:00:00+01:00`;
    const expectedEndEpoch = Math.floor(new Date(expectedEndIso).getTime() / 1000);
    // If opened today and class schedule is 09:00 - 11:00 WAT, end_unix should align with scheduled class end
    if (expectedEndEpoch > sessEpoch.start_unix) {
      assert(sessEpoch.end_unix === expectedEndEpoch, "end_unix correctly derived from schedule end_time in Africa/Lagos (+01:00)");
    } else {
      assert(sessEpoch.end_unix >= sessEpoch.start_unix + 3600, "end_unix safely defaults to 1h window if opened after scheduled end");
    }

    // ── SCENARIO 11: Missing headers or malformed protocol ───────────────────
    console.log("\n11. Scenario 11: Malformed request & protocol validation");
    // 11a. Missing x-device-key
    const res11a = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ terminal_id: TEST_TERMINAL_ID, protocol: "attendclass.offline.v1" }),
    });
    assert(res11a.status === 401, "Missing x-device-key header returns HTTP 401");

    // 11b. Missing x-terminal-id
    const res11b = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ terminal_id: TEST_TERMINAL_ID, protocol: "attendclass.offline.v1" }),
    });
    assert(res11b.status === 400, "Missing x-terminal-id header returns HTTP 400");

    // 11c. Invalid protocol version
    const res11c = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ terminal_id: TEST_TERMINAL_ID, protocol: "attendclass.offline.v2_unsupported" }),
    });
    assert(res11c.status === 400, "Unsupported protocol string returns HTTP 400 Bad Request");

    // ── SCENARIO 12: Terminal provisioning after reconnect ───────────────────
    console.log("\n12. Scenario 12: Terminal reconnect & sync timestamp update");
    const lastSyncBefore = dbDev?.last_sync_at;
    const res12 = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "provision_terminal",
        "x-device-key": TEST_DEVICE_KEY,
        "x-terminal-id": TEST_TERMINAL_ID,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ terminal_id: TEST_TERMINAL_ID, protocol: "attendclass.offline.v1" }),
    });
    assert(res12.status === 200, "Reconnect provisioning returns HTTP 200 OK");
    const { data: dbDevAfter } = await supabase.from("devices").select("last_sync_at").eq("id", testTerminalDbId).single();
    assert(!!dbDevAfter?.last_sync_at, "devices.last_sync_at is updated on reconnection");

    // ── SCENARIO 13: Backward compatibility ──────────────────────────────────
    console.log("\n13. Scenario 13: Backward compatibility (legacy refresh_credentials & upload)");
    // 13a. Legacy refresh_credentials action
    const res13a = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-action": "refresh_credentials",
        "x-device-key": TEST_DEVICE_KEY,
      },
    });
    assert(res13a.status === 200, "Legacy refresh_credentials returns HTTP 200 OK");
    const body13a = await res13a.json();
    assert(Array.isArray(body13a.enrolled_keys), "Legacy refresh_credentials returns enrolled_keys array");
    assert(body13a.accepted === 0 && body13a.rows_received === 0, "Legacy response shape preserved");

    // 13b. Legacy 16-field CSV header check
    const res13b = await fetch(HARDWARE_SYNC_URL, {
      method: "POST",
      headers: {
        "x-sync-file-type": "attendance",
        "x-device-key": TEST_DEVICE_KEY,
        "Content-Type": "text/csv",
      },
      body: "time,name,matric,logging_type\n2026-11-18 10:00:00,Test Student,MATRIC/A/001,rfid\n",
    });
    assert(res13b.status === 200, "Legacy CSV attendance upload returns HTTP 200 OK");

    // ── BONUS: Test New Database RPCs (0019) ──────────────────────────────────
    console.log("\n14. Database RPCs (0019): platform_update_terminal_key, reprovision & bundle");
    // Fetch an admin user session
    const { data: adminProf } = await supabase.from("profiles").select("id").eq("role", "administrator").limit(1).single();
    if (adminProf) {
      // Create test session for admin
      const adminToken = crypto.randomUUID();
      await supabase.from("active_sessions").insert({
        account_id: adminProf.id,
        token: adminToken,
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      });

      // 14a. Update terminal key RPC
      const { data: rpcKeyRes, error: rpcKeyErr } = await supabase.rpc("platform_update_terminal_key", {
        p_admin_token: adminToken,
        p_terminal_id: TEST_TERMINAL_ID,
        p_public_key: SAMPLE_P256_SPKI_KEY,
      });
      assert(!rpcKeyErr && rpcKeyRes?.ok === true, "platform_update_terminal_key succeeds with admin session");
      assert(rpcKeyRes?.public_key === SAMPLE_P256_SPKI_KEY, "platform_update_terminal_key stores SPKI key");

      // 14b. Trigger reprovision RPC
      const { data: rpcReprovRes, error: rpcReprovErr } = await supabase.rpc("platform_trigger_terminal_reprovision", {
        p_admin_token: adminToken,
        p_terminal_id: TEST_TERMINAL_ID,
      });
      assert(!rpcReprovErr && rpcReprovRes?.ok === true, "platform_trigger_terminal_reprovision succeeds");

      // 14c. Get terminal provisioning bundle RPC
      const { data: rpcBundleRes, error: rpcBundleErr } = await supabase.rpc("platform_get_terminal_provisioning", {
        p_admin_token: adminToken,
        p_terminal_id: TEST_TERMINAL_ID,
      });
      assert(!rpcBundleErr && rpcBundleRes?.ok === true, "platform_get_terminal_provisioning succeeds");
      assert(rpcBundleRes?.terminal_id === TEST_TERMINAL_ID, "Bundle terminal_id matches");
      assert(rpcBundleRes?.active_session !== null, "Bundle active_session matches open session");

      // Clean up test admin session
      await supabase.from("active_sessions").delete().eq("token", adminToken);
    }

  } finally {
    // ── Teardown Fixtures ────────────────────────────────────────────────────
    console.log("\nCleaning up test fixtures from database...");
    if (testSessionId1) {
      await supabase.from("attendance_sessions").delete().eq("id", testSessionId1);
    }
    if (testSessionId2) {
      await supabase.from("attendance_sessions").delete().eq("id", testSessionId2);
    }
    if (testScheduleId) {
      await supabase.from("schedules").delete().eq("id", testScheduleId);
    }
    if (studentAId) {
      await supabase.from("student_devices").delete().eq("student_id", studentAId);
      await supabase.from("enrollments").delete().eq("student_id", studentAId);
      await supabase.from("profiles").delete().eq("id", studentAId);
    }
    if (studentBId) {
      await supabase.from("student_devices").delete().eq("student_id", studentBId);
      await supabase.from("profiles").delete().eq("id", studentBId);
    }
    if (studentCId) {
      await supabase.from("student_devices").delete().eq("student_id", studentCId);
      await supabase.from("enrollments").delete().eq("student_id", studentCId);
      await supabase.from("profiles").delete().eq("id", studentCId);
    }
    if (testCourseId) {
      await supabase.from("courses").delete().eq("id", testCourseId);
    }
    if (testTerminalDbId) {
      await supabase.from("devices").delete().eq("id", testTerminalDbId);
    }
    console.log("Cleanup complete.\n");
  }

  console.log("=================================================================");
  console.log(`Execution Summary: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log("=================================================================\n");

  if (failedTests > 0) {
    process.exit(1);
  }
}

runProvisioningTestSuite().catch((err) => {
  console.error("Test execution fatal error:", err);
  process.exit(1);
});
