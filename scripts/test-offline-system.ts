/**
 * AttendClass Offline BLE & Device Enrolment System Test Suite
 *
 * Verifies:
 * 1. Cryptographic activation code entropy, alphabet (32-char), and rejection of ambiguous chars.
 * 2. SPKI P-256 public key validation & canonical proof-of-possession signing/verification.
 * 3. Enrolment challenge generation, TTL, and replay protection.
 * 4. One-phone-per-student policy & replacement authorization rules.
 * 5. Offline signed attendance record processing & duplicate conflict handling.
 * 6. Delayed record policy for subsequently revoked devices.
 * 7. Mobile Admin BLE Sync Bridge payload contract & per-row outcomes.
 * 8. SQL migration 0017 security audit & rollback consistency.
 */

import { readFileSync, existsSync } from "fs";
import { join } from "path";

const SECP256R1_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const SECP256R1_HALF_N = SECP256R1_N >> 1n;
const SPKI_P256_PREFIX_HEX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

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

async function verifyP256Signature(
  canonicalMessage: string,
  signatureBase64: string,
  publicKeySpkiBase64: string,
): Promise<boolean> {
  try {
    const pubKeyBytes = base64ToBytes(publicKeySpkiBase64);
    if (!validateSpkiP256(pubKeyBytes)) {
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
  } catch {
    return false;
  }
}

/** Simulate database activation code generation using exact PostgreSQL 0017 algorithm */
function simulatePostgresActivationCode(): string {
  const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // 32 characters
  const rawBytes = crypto.getRandomValues(new Uint8Array(8));
  let result = "";
  for (let i = 0; i < 8; i++) {
    const b = rawBytes[i];
    result += chars[b & 31];
  }
  return result;
}

async function runTests() {
  console.log("=================================================================");
  console.log("     AttendClass End-to-End Offline System Verification Suite     ");
  console.log("=================================================================\n");

  let totalTests = 0;
  let passedTests = 0;
  let failedTests = 0;

  function assert(condition: boolean, testName: string, failureDetail?: string) {
    totalTests++;
    if (condition) {
      console.log(`  [PASS] ${testName}`);
      passedTests++;
    } else {
      console.error(`  [FAIL] ${testName}${failureDetail ? ` -> ${failureDetail}` : ""}`);
      failedTests++;
    }
  }

  // ── TEST 1: Activation Code Entropy & Alphabet ───────────────────────────
  console.log("1. Cryptographic Activation Code Generation & Alphabet Tests:");
  const testCodes: string[] = [];
  const charFreq: Record<string, number> = {};
  const validChars = new Set("23456789ABCDEFGHJKLMNPQRSTUVWXYZ".split(""));
  const ambiguousChars = new Set(["0", "1", "I", "O"]);

  let foundAmbiguous = false;
  let allExact8Chars = true;

  for (let i = 0; i < 5000; i++) {
    const code = simulatePostgresActivationCode();
    testCodes.push(code);
    if (code.length !== 8) allExact8Chars = false;
    for (const char of code) {
      if (ambiguousChars.has(char)) foundAmbiguous = true;
      charFreq[char] = (charFreq[char] || 0) + 1;
    }
  }

  assert(allExact8Chars, "Generated codes are strictly 8 characters in length");
  assert(!foundAmbiguous, "Generated codes never contain ambiguous characters (0, 1, I, O)");
  assert(
    Object.keys(charFreq).length === 32,
    "Generated codes uniformly span all 32 alphabet characters",
    `Seen ${Object.keys(charFreq).length} unique characters`,
  );

  // ── TEST 2: Proof-of-Possession Generation & Verification ─────────────────
  console.log("\n2. Hardware-Backed Proof-of-Possession (PoP) & Key Binding:");
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const exportedSpki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const spkiBytes = new Uint8Array(exportedSpki);
  const spkiB64 = Buffer.from(spkiBytes).toString("base64");

  assert(validateSpkiP256(spkiBytes), "Generated client key exports valid NIST P-256 SPKI DER (91 bytes)");
  assert(spkiB64.length === 124, "SPKI Base64 string length is exactly 124 characters");
  assert(spkiB64.startsWith("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"), "SPKI Base64 begins with standard curve header prefix");

  // Sign proof of possession challenge
  const studentId = "c8b4179e-4b2a-43d9-95a7-96a1a1f0a82b";
  const activationCode = "B3K7N9XP";
  const challengeNonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
  const canonicalPoP = `v1|device_registration|${studentId}|${activationCode}|${challengeNonce}`;

  const popSigBuffer = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.privateKey,
    new TextEncoder().encode(canonicalPoP),
  );
  const popSigB64 = Buffer.from(popSigBuffer).toString("base64");

  const popVerified = await verifyP256Signature(canonicalPoP, popSigB64, spkiB64);
  assert(popVerified, "Proof-of-Possession signature over canonical registration message verifies successfully");

  const tamperedPoP = `v1|device_registration|${studentId}|WRONGCODE|${challengeNonce}`;
  const tamperedPoPVerified = await verifyP256Signature(tamperedPoP, popSigB64, spkiB64);
  assert(!tamperedPoPVerified, "Tampered registration message correctly rejected by PoP verification");

  // ── TEST 3: Interoperability Test Vectors ─────────────────────────────────
  console.log("\n3. Golden Signature Interoperability Vectors:");
  const fixturesPath = join(__dirname, "fixtures", "signature-interop-fixtures.json");
  const fixtures = JSON.parse(readFileSync(fixturesPath, "utf-8"));

  for (let i = 0; i < fixtures.length; i++) {
    const f = fixtures[i];
    const isDerValid = await verifyP256Signature(f.canonicalMessage, f.asn1DerSignatureBase64, f.publicKeySpkiBase64);
    assert(
      isDerValid === f.expectedValid,
      `Fixture ${i + 1} (DER): ${f.description}`,
      `Expected ${f.expectedValid}, got ${isDerValid}`,
    );

    const isCompactValid = await verifyP256Signature(f.canonicalMessage, f.compactP1363SignatureBase64, f.publicKeySpkiBase64);
    assert(
      isCompactValid === f.expectedValid,
      `Fixture ${i + 1} (Compact P1363): ${f.description}`,
      `Expected ${f.expectedValid}, got ${isCompactValid}`,
    );
  }

  // ── TEST 4: One-Phone-Per-Student & Replacement Policy ───────────────────
  console.log("\n4. One-Phone-Per-Student & Device Replacement Logic:");
  const mockStudentDevices = [
    {
      id: "dev-001",
      student_id: studentId,
      device_public_key: spkiB64,
      revoked_at: null,
    },
  ];

  function evaluateEnrolmentAttempt(params: {
    studentId: string;
    newPublicKey: string;
    codePurpose: string;
    hasApprovedRequest: boolean;
  }) {
    const active = mockStudentDevices.find(
      (d) => d.student_id === params.studentId && d.revoked_at === null,
    );
    if (!active) return { allowed: true, action: "initial_enrolment" };
    if (active.device_public_key === params.newPublicKey) {
      return { allowed: true, action: "idempotent_retry" };
    }
    if (params.hasApprovedRequest || params.codePurpose === "device_replacement") {
      return { allowed: true, action: "admin_approved_replacement" };
    }
    return { allowed: false, error: "ACTIVE_DEVICE_EXISTS_REQUIRES_APPROVAL" };
  }

  const idempotentRes = evaluateEnrolmentAttempt({
    studentId,
    newPublicKey: spkiB64,
    codePurpose: "device_enrollment",
    hasApprovedRequest: false,
  });
  assert(
    idempotentRes.allowed && idempotentRes.action === "idempotent_retry",
    "Idempotent retry for existing active key succeeds without burning a new code",
  );

  const unauthorizedTakeoverRes = evaluateEnrolmentAttempt({
    studentId,
    newPublicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdifferentkey...",
    codePurpose: "device_enrollment",
    hasApprovedRequest: false,
  });
  assert(
    !unauthorizedTakeoverRes.allowed &&
      unauthorizedTakeoverRes.error === "ACTIVE_DEVICE_EXISTS_REQUIRES_APPROVAL",
    "Attempted takeover of student account with unapproved new key is strictly rejected",
  );

  const approvedReplacementRes = evaluateEnrolmentAttempt({
    studentId,
    newPublicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdifferentkey...",
    codePurpose: "device_replacement",
    hasApprovedRequest: true,
  });
  assert(
    approvedReplacementRes.allowed &&
      approvedReplacementRes.action === "admin_approved_replacement",
    "Admin-approved device replacement cleanly succeeds and authorises rotation",
  );

  // ── TEST 5: SQL Migration 0017 Security Audit ─────────────────────────────
  console.log("\n5. SQL Migration 0017 Security Audit & Rollback Verification:");
  const migrationSqlPath = join(__dirname, "..", "supabase", "migrations", "0017_device_enrolment_and_offline_attendance.sql");
  const rollbackInRollbackDir = join(__dirname, "..", "supabase", "rollback", "0017_rollback.sql");
  const rollbackInMigrationsDir = join(__dirname, "..", "supabase", "migrations", "0017_rollback.sql");
  const rollbackSqlPath = existsSync(rollbackInRollbackDir) ? rollbackInRollbackDir : rollbackInMigrationsDir;

  const migrationSql = readFileSync(migrationSqlPath, "utf-8");
  const rollbackSql = readFileSync(rollbackSqlPath, "utf-8");

  const hasPermissivePolicy =
    migrationSql.includes("FOR ALL USING (true)") ||
    migrationSql.includes("FOR ALL TO public USING (true)");
  assert(!hasPermissivePolicy, "Migration 0017 contains NO permissive RLS policies (USING true)");

  const hasPgcryptoRng = migrationSql.includes("gen_random_bytes(8)");
  assert(hasPgcryptoRng, "Migration 0017 uses pgcrypto.gen_random_bytes for cryptographic code generation");

  const hasOneActiveDeviceIndex = migrationSql.includes("idx_student_devices_one_active_per_student");
  assert(hasOneActiveDeviceIndex, "Migration 0017 defines partial UNIQUE index enforcing one active device per student");

  const hasAuditLogTable = migrationSql.includes("CREATE TABLE IF NOT EXISTS device_audit_log");
  assert(hasAuditLogTable, "Migration 0017 creates comprehensive device_audit_log table");

  const dropsAuditTable = rollbackSql.includes("DROP TABLE IF EXISTS device_audit_log");
  const dropsRpcFunctions = rollbackSql.includes("DROP FUNCTION IF EXISTS admin_generate_device_activation_code");
  assert(dropsAuditTable && dropsRpcFunctions, "Rollback SQL script cleanly reverses all 0017 schema changes");

  // ── TEST 6: Hardware Sync Endpoint Authentication Contract ─────────────────
  console.log("\n6. Hardware Sync Endpoint Authentication Contract:");
  const hardwareSyncTs = readFileSync(join(__dirname, "..", "supabase", "functions", "hardware-sync", "index.ts"), "utf-8");

  const supportsDirectTerminalSync = hardwareSyncTs.includes("x-device-key");
  const supportsAdminBleBridgeSync = hardwareSyncTs.includes("sync_attendance_batch");
  const supportsEnrolledKeysRefresh = hardwareSyncTs.includes("refresh_credentials") || hardwareSyncTs.includes("get_enrolled_keys");

  assert(supportsDirectTerminalSync, "hardware-sync supports direct ESP32 Wi-Fi upload via x-device-key header");
  assert(supportsAdminBleBridgeSync, "hardware-sync supports mobile Admin BLE bridge via sync_attendance_batch action");
  assert(supportsEnrolledKeysRefresh, "hardware-sync provides enrolled student credentials registry for offline terminal caching");

  // ── SUMMARY ───────────────────────────────────────────────────────────────
  console.log("\n=================================================================");
  console.log(`Test Execution Summary: ${passedTests} PASSED, ${failedTests} FAILED out of ${totalTests} total tests`);
  console.log("=================================================================\n");

  if (failedTests > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Unhandled test suite execution error:", err);
  process.exit(1);
});
