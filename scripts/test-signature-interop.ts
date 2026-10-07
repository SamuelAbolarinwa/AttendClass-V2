/**
 * Shared NIST P-256 Signature Interoperability Verification for Backend
 * Tests hardware-sync WebCrypto implementation against SIGNATURE_INTEROP_VECTORS.
 */

const SPKI_P256_PREFIX_HEX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
const SECP256R1_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const SECP256R1_HALF_N = SECP256R1_N >> 1n;

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
  } catch (err) {
    return false;
  }
}

const SIGNATURE_INTEROP_VECTORS = [
  {
    description: "Valid ECDSA P-256 signature over canonical attendance submission",
    canonicalMessage:
      "v1|submission|evt-test-101|cred-p256-01|v1|ECDSA_P256_SHA256|std-uuid-001|2021/1/12345CP|TERM_01|sess_20261006|challenge_nonce_32_bytes_test|1791298800|phone_os",
    publicKeySpkiBase64:
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE77edo9o0tvejrv0kEzHJqePFlVqYYP8fg9lqyJOMe8ONKuImJsIgYXA6VNK0KTMWg/OfiBwipkkdjXnra3aKRg==",
    asn1DerSignatureBase64:
      "MEQCIGytQ2CkHxnnHniU5FTEt1IZ/1YgmrHzG7tFyMs7Jit3AiBrYvr228g50rogqwSbw5vJvZ9TMwd6Jp/0rdSZIhcvoQ==",
    compactP1363SignatureBase64:
      "bK1DYKQfGeceeJTkVMS3Uhn/ViCasfMbu0XIyzsmK3drYvr228g50rogqwSbw5vJvZ9TMwd6Jp/0rdSZIhcvoQ==",
    expectedValid: true,
  },
  {
    description: "Tampered canonical message must fail verification",
    canonicalMessage:
      "v1|submission|evt-test-101|cred-p256-01|v1|ECDSA_P256_SHA256|std-uuid-001|2021/1/99999CP|TERM_01|sess_20261006|challenge_nonce_32_bytes_test|1791298800|phone_os",
    publicKeySpkiBase64:
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE77edo9o0tvejrv0kEzHJqePFlVqYYP8fg9lqyJOMe8ONKuImJsIgYXA6VNK0KTMWg/OfiBwipkkdjXnra3aKRg==",
    asn1DerSignatureBase64:
      "MEQCIGytQ2CkHxnnHniU5FTEt1IZ/1YgmrHzG7tFyMs7Jit3AiBrYvr228g50rogqwSbw5vJvZ9TMwd6Jp/0rdSZIhcvoQ==",
    compactP1363SignatureBase64:
      "bK1DYKQfGeceeJTkVMS3Uhn/ViCasfMbu0XIyzsmK3drYvr228g50rogqwSbw5vJvZ9TMwd6Jp/0rdSZIhcvoQ==",
    expectedValid: false,
  },
  {
    description: "Tampered signature bytes must fail verification",
    canonicalMessage:
      "v1|submission|evt-test-101|cred-p256-01|v1|ECDSA_P256_SHA256|std-uuid-001|2021/1/12345CP|TERM_01|sess_20261006|challenge_nonce_32_bytes_test|1791298800|phone_os",
    publicKeySpkiBase64:
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE77edo9o0tvejrv0kEzHJqePFlVqYYP8fg9lqyJOMe8ONKuImJsIgYXA6VNK0KTMWg/OfiBwipkkdjXnra3aKRg==",
    asn1DerSignatureBase64:
      "MEQDIGytQ2CkHxnnHniU5FTEt1IZ/1YgmrHzG7tFyMs7Jit3AiBrYvr228g50rogqwSbw5vJvZ9TMwd6Jp/0rdSZIhcvoQ==",
    compactP1363SignatureBase64:
      "cK1DYKQfGeceeJTkVMS3Uhn/ViCasfMbu0XIyzsmK3drYvr228g50rogqwSbw5vJvZ9TMwd6Jp/0rdSZIhcvoQ==",
    expectedValid: false,
  },
];

async function run() {
  console.log("=== Running Backend WebCrypto Signature Interoperability Tests ===");
  let passed = 0;
  let failed = 0;

  for (let i = 0; i < SIGNATURE_INTEROP_VECTORS.length; i++) {
    const v = SIGNATURE_INTEROP_VECTORS[i];
    process.stdout.write(`Vector ${i + 1}: ${v.description} ... `);

    // 1. Verify DER signature
    const derResult = await verifyP256Signature(v.canonicalMessage, v.asn1DerSignatureBase64, v.publicKeySpkiBase64);
    if (derResult !== v.expectedValid) {
      console.log(`FAILED (DER: expected ${v.expectedValid}, got ${derResult})`);
      failed++;
      continue;
    }

    // 2. Verify Compact signature
    const compactResult = await verifyP256Signature(v.canonicalMessage, v.compactP1363SignatureBase64, v.publicKeySpkiBase64);
    if (compactResult !== v.expectedValid) {
      console.log(`FAILED (Compact: expected ${v.expectedValid}, got ${compactResult})`);
      failed++;
      continue;
    }

    // 3. Bi-directional conversion test for valid vector
    if (v.expectedValid) {
      const convertedCompact = derToCompactSignature(base64ToBytes(v.asn1DerSignatureBase64));
      const convertedCompactB64 = Buffer.from(convertedCompact).toString("base64");
      if (convertedCompactB64 !== v.compactP1363SignatureBase64) {
        console.log(`FAILED (DER->Compact mismatch)`);
        failed++;
        continue;
      }

      const convertedDer = compactToDerSignature(base64ToBytes(v.compactP1363SignatureBase64));
      const convertedDerB64 = Buffer.from(convertedDer).toString("base64");
      const convertedDerResult = await verifyP256Signature(v.canonicalMessage, convertedDerB64, v.publicKeySpkiBase64);
      if (!convertedDerResult) {
        console.log(`FAILED (Compact->DER failed verification)`);
        failed++;
        continue;
      }
    }

    console.log("PASSED");
    passed++;
  }

  // SPKI validation test
  process.stdout.write("SPKI Structure Validation ... ");
  const validSpki = validateSpkiP256(base64ToBytes(SIGNATURE_INTEROP_VECTORS[0].publicKeySpkiBase64));
  const invalidLength = validateSpkiP256(new Uint8Array(90));
  const invalidHeader = validateSpkiP256(new Uint8Array(91));
  if (validSpki && !invalidLength && !invalidHeader) {
    console.log("PASSED");
    passed++;
  } else {
    console.log("FAILED");
    failed++;
  }

  console.log(`=== Summary: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
}

run();
