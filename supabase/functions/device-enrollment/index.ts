/**
 * device-enrollment — Supabase Edge Function
 *
 * Implements:
 * 1. Ephemeral server challenge issuance for Proof-of-Possession (PoP).
 * 2. Cryptographic verification of ECDSA P-256 PoP signature before binding public key.
 * 3. Enrolment delegation to hardened platform_enroll_device RPC with atomic safety.
 * 4. Online session renewal via registered-device proof-of-possession.
 */

import { createClient, SupabaseClient } from "jsr:@supabase/supabase-js@2";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, authorization, apikey",
};

function json(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

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

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON request body" }, 400);
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const action = body.action || "enroll_device";

  // ══════════════════════════════════════════════════════════════════════════
  // ACTION: request_challenge
  // ══════════════════════════════════════════════════════════════════════════
  if (action === "request_challenge") {
    const sessionToken = body.session_token || body.token;
    if (!sessionToken) {
      return json({ error: "session_token required" }, 401);
    }

    const { data: challengeData, error: challengeErr } = await supabase.rpc(
      "platform_request_enrollment_challenge",
      { p_token: sessionToken }
    );

    if (challengeErr || !challengeData || !challengeData.ok) {
      return json({ error: challengeData?.error || challengeErr?.message || "Failed to generate challenge" }, 400);
    }

    return json({
      ok: true,
      challenge: challengeData.challenge,
      expires_at: challengeData.expires_at,
    });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ACTION: enroll_device (with Proof-of-Possession verification)
  // ══════════════════════════════════════════════════════════════════════════
  if (action === "enroll_device") {
    const sessionToken = body.session_token || body.token;
    const activationCode = body.activation_code?.trim().toUpperCase();
    const publicKey = body.device_public_key?.trim();
    const platform = body.platform || "android";
    const deviceName = body.device_name || "Mobile Device";
    const challenge = body.challenge?.trim();
    const signature = body.pop_signature || body.signature;

    if (!sessionToken || !activationCode || !publicKey) {
      return json({ error: "Missing required parameters: session_token, activation_code, and device_public_key are required" }, 400);
    }

    // 1. Authenticate user session
    const { data: sess, error: sessErr } = await supabase
      .from("active_sessions")
      .select("account_id, expires_at")
      .eq("token", sessionToken)
      .gt("expires_at", new Date().toISOString())
      .maybeSingle();

    if (sessErr || !sess) {
      return json({ error: "Unauthorized: Invalid or expired session token" }, 401);
    }

    const studentId = sess.account_id;

    // 2. Cryptographic Proof-of-Possession Verification (if challenge provided)
    if (challenge && signature) {
      // Validate challenge existence & unexpired state in DB
      const { data: challengeRow, error: chErr } = await supabase
        .from("device_enrollment_challenges")
        .select("id, expires_at, consumed_at")
        .eq("student_id", studentId)
        .eq("challenge", challenge)
        .is("consumed_at", null)
        .gt("expires_at", new Date().toISOString())
        .maybeSingle();

      if (chErr || !challengeRow) {
        return json({ error: "Proof of possession challenge expired or already consumed" }, 400);
      }

      // Canonical Proof of Possession message format:
      // v1|device_registration|{student_id}|{activation_code}|{challenge}
      const canonicalPoP = `v1|device_registration|${studentId}|${activationCode}|${challenge}`;
      const isPoPValid = await verifyP256Signature(canonicalPoP, signature, publicKey);

      if (!isPoPValid) {
        return json({
          error: "PROOF_OF_POSSESSION_FAILED: Cryptographic signature does not match private key possession for the submitted public key",
        }, 400);
      }
    }

    // 3. Delegate to hardened platform_enroll_device RPC
    const { data: enrollResult, error: enrollErr } = await supabase.rpc(
      "platform_enroll_device",
      {
        p_token: sessionToken,
        p_activation_code: activationCode,
        p_device_public_key: publicKey,
        p_platform: platform,
        p_device_name: deviceName,
        p_algorithm: "ECDSA_P256_SHA256",
        p_credential_id: body.credential_id || null,
        p_challenge: challenge || null,
        p_signature: signature || null,
      }
    );

    if (enrollErr) {
      return json({ error: enrollErr.message }, 400);
    }

    if (!enrollResult || !enrollResult.ok) {
      return json({ error: enrollResult?.error || "Device enrolment failed" }, 400);
    }

    return json(enrollResult);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ACTION: renew_session (Registered-Device Proof-of-Possession)
  // ══════════════════════════════════════════════════════════════════════════
  if (action === "renew_session") {
    const deviceId = body.device_id;
    const challenge = body.challenge?.trim();
    const signature = body.signature?.trim();

    if (!deviceId || !challenge || !signature) {
      return json({ error: "device_id, challenge, and signature required for session renewal" }, 400);
    }

    // Look up active registered device
    const { data: device, error: devErr } = await supabase
      .from("student_devices")
      .select("id, student_id, device_public_key, algorithm, revoked_at")
      .eq("id", deviceId)
      .is("revoked_at", null)
      .maybeSingle();

    if (devErr || !device) {
      return json({ error: "Device is not registered or has been revoked" }, 401);
    }

    // Canonical renewal message:
    // v1|session_renewal|{device_id}|{student_id}|{challenge}
    const canonicalRenewal = `v1|session_renewal|${deviceId}|${device.student_id}|${challenge}`;
    const isValid = await verifyP256Signature(canonicalRenewal, signature, device.device_public_key);

    if (!isValid) {
      return json({ error: "Cryptographic proof of possession failed for session renewal" }, 401);
    }

    // Issue fresh 12-hour active session
    const { data: newSession, error: sessErr } = await supabase
      .from("active_sessions")
      .insert({ account_id: device.student_id })
      .select("token, expires_at")
      .single();

    if (sessErr || !newSession) {
      return json({ error: "Failed to generate renewed session" }, 500);
    }

    return json({
      ok: true,
      token: newSession.token,
      expires_at: newSession.expires_at,
      message: "Session successfully renewed via hardware key proof of possession",
    });
  }

  return json({ error: `Unknown action: ${action}` }, 400);
});
