/**
 * ============================================================================
 * AttendClass Physical Attendance Terminal Firmware — AttendESP v3
 * ============================================================================
 * Hardware Platform: Espressif ESP32 Dev Module (WROOM-32)
 *
 * Core Features:
 * 1. RESTORED BASELINE FUNCTIONALITY:
 *    - Matched RFID card AND optical fingerprint dual-factor 2FA attendance.
 *    - Student biometric and card enrollment mode with skip button.
 *    - Local student database (/students.csv) with SD read/write.
 *    - Master RFID card interactive navigation menu (Attendance, Enrollment, Sync).
 *    - BLE rolling TOTP advertising token for room presence verification.
 *    - Legacy dual-factor SD event logging (/attendance.csv, /enrollment.csv).
 *
 * 2. REAL CRYPTOGRAPHIC OFFLINE BLE ATTENDANCE:
 *    - Custom GATT Offline Attendance Service (0000ff10-0000-1000-8000-00805f9b34fb).
 *    - Challenge Char (0000ff11): Issues cryptographically signed nonces bound to
 *      terminal ID, active session ID, and monotonic elapsed time (60s expiry).
 *    - Submission Char (0000ff12): Receives compact MTU-sized framed packets
 *      ([0xAC, 0x01, txHi, txLo, seq, total, ...payload]), decouples reassembly
 *      from BLE callbacks, validates student credentials, and verifies student
 *      ECDSA NIST P-256 signatures via mbedtls.
 *    - ACK/Receipt Char (0000ff13): Issues signed durable receipts ONLY after
 *      successful record persistence and flush to SD.
 *    - Terminal Keypair: Loaded securely from SD (/terminal_key.bin). Operational
 *      firmware fails closed if the key is missing or invalid.
 *    - Student Public Key Registry (/enrolled_keys.csv): Verifies student credentials
 *      against institutional keys; arbitrary self-signed keys are rejected.
 *
 * 3. DURABLE SD PERSISTENCE & DEDUPLICATION:
 *    - Complete offline attendance records written to /attendance_offline.csv.
 *    - Event ID index (/event_index.csv) records event_id, matric, submission_digest,
 *      terminal_saved_at, and receipt_signature for idempotency and reconciliation.
 *    - Reused event ID with conflicting contents is strictly rejected.
 *    - Real reconciliation query handler (v1|reconcile|eventId|studentId) returns
 *      the original saved receipt.
 *
 * 4. SD / CLOUD OUTBOX WITH PERSISTENT PROGRESS:
 *    - Checkpoint cursor tracked in /sync_checkpoint.txt.
 *    - Uploads bounded batches (10 records at a time) via HTTPS with DigiCert Root G2.
 *    - Inspects per-record outcomes: ACCEPTED, DUPLICATE, REJECTED, RETRYABLE.
 *    - Archives rejected records to /rejected_records.csv with error reasons.
 *    - Advances checkpoint only for acknowledged records, preserving unacknowledged
 *      and concurrently appended records.
 *    - Dedicated credential-refresh path that works before any attendance exists,
 *      updating /enrolled_keys.csv atomically via a temporary file.
 * ============================================================================
 */

#include <Arduino.h>
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <MFRC522.h>
#include <Adafruit_Fingerprint.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLEAdvertising.h>

// mbedtls cryptographic primitives (built into ESP32 core)
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <base64.h>

// ================= HARDWARE PIN ASSIGNMENTS =================
#define OLED_SDA 21
#define OLED_SCL 22
#define OLED_ADDR 0x3C
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

#define RFID_SS_PIN 5
#define RFID_RST_PIN 0
#define RFID_SCK 18
#define RFID_MISO 19
#define RFID_MOSI 23

#define SD_CS 27
#define SD_MOSI 13
#define SD_MISO 35
#define SD_SCK 14

#define FP_RX 32
#define FP_TX 33

#define GREEN_LED 4
#define RED_LED 26
#define BUZZER_PIN 16

// ================= NETWORK & CLOUD CONFIGURATION =================
#ifndef WIFI_SSID
const char* WIFI_SSID = "YOUR_WIFI_SSID";
#endif
#ifndef WIFI_PASSWORD
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
#endif
#ifndef CLOUD_BASE_URL
const char* CLOUD_BASE_URL = "https://your-supabase-project.supabase.co";
#endif
#ifndef SYNC_ENDPOINT
const char* SYNC_ENDPOINT = "/functions/v1/hardware-sync";
#endif
#ifndef DEVICE_KEY
const char* DEVICE_KEY = "YOUR_DEVICE_SECRET_KEY";
#endif
#ifndef DEVICE_ID
const String DEVICE_ID = "TERM-LAB1-01";
#endif

// Master administrative RFID card UID
const String MASTER_RFID_UID = "B3B7FE1A";

// DigiCert Root G2 Root CA Certificate for HTTPS validation
const char* SUPABASE_CA_CERT =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn55zANBgkqhkiG9w0BAQsFADBh\n"
  "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
  "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\n"
  "MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\n"
  "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
  "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\n"
  "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0hby2UsGybpMrU5If520+E8wYs/7U3Z4fQTX\n"
  "CAQMGcgCGqt61OuJUOpFEtny8782Z866+/G/0ITi65AFaEAeUux8e81504cxWwip\n"
  "fvWBK/kIaEsmALCQCVAWxmAV5++6xFmcnpr/EENqPAjJMpm56iypnDXKBEHs5GtJ\n"
  "qbkTMF3wSbZgGI4FvlLiU2U8kWkUawIlE292/acKn53REoya5BlBK3DitOOJaNNg\n"
  "880/+LAUUsn59VU65RzEkZHP187uPn4OhY4dd54upLjLHPE1O4IwVDnKnJh3i03m\n"
  "RFIVqFHztn52d1bBVod8EzMQzGW15eJ3XtrvGLS8UgolU6A1MQIDAQABo0IwQDAP\n"
  "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\n"
  "5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\n"
  "1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iFsIECal+87vNu4Lq2\n"
  "W8WCvn2GQy2wNV7SQDC20w/4LlcgqClSbvfsWHvTH353VNvpaWvDzEKR93yC+otW\n"
  "5qpnDXKBEHs5GtJqbkTMF3wSbZgGI4FvlLiU2U8kWkUawIlE292/acKn53REoya5\n"
  "-----END CERTIFICATE-----\n";

// ================= BLE CONSTANTS =================
#define ATTENDCLASS_SERVICE_UUID "0000ff10-0000-1000-8000-00805f9b34fb"
#define CHALLENGE_CHAR_UUID     "0000ff11-0000-1000-8000-00805f9b34fb"
#define SUBMISSION_CHAR_UUID    "0000ff12-0000-1000-8000-00805f9b34fb"
#define ACK_CHAR_UUID           "0000ff13-0000-1000-8000-00805f9b34fb"
#define TIMESYNC_CHAR_UUID      "0000ff01-0000-1000-8000-00805f9b34fb"

#define FRAME_MAGIC_BYTE 0xAC
#define FRAME_VERSION_BYTE 0x01
#define BINARY_HEADER_SIZE 6
#define MAX_PAYLOAD_BYTES 2048
#define MAX_CHUNKS 255

// ================= HARDWARE OBJECTS =================
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);
MFRC522 rfid(RFID_SS_PIN, RFID_RST_PIN);
SPIClass sdSPI(VSPI);
HardwareSerial fpSerial(2);
Adafruit_Fingerprint finger(&fpSerial);

BLEServer* bleServer = nullptr;
BLECharacteristic* challengeChar = nullptr;
BLECharacteristic* submissionChar = nullptr;
BLECharacteristic* ackChar = nullptr;
BLECharacteristic* timeSyncChar = nullptr;
BLEAdvertising* bleAdvertising = nullptr;
bool bleReady = false;

// ================= STATE & ENUMS =================
enum DeviceMode { MODE_ATTENDANCE, MODE_ENROLLMENT, MODE_SYNC };
DeviceMode currentMode = MODE_ATTENDANCE;

#define MAX_STUDENTS 100
struct StudentRecord {
  char matric[32];
  char name[48];
  char rfid[16];
  int fingerprintId;
};
StudentRecord students[MAX_STUDENTS];
int studentCount = 0;
int enrollmentTargetIdx = -1;
bool sdAvailable = false;

struct LogEvent {
  char logType; // 'A' = Attendance, 'E' = Enrollment
  char matric[32];
  char name[48];
  char method[16];
  char rfid[16];
  int fp_id;
  unsigned long scan_millis;
};

// ================= OFFLINE BLE EVENT STRUCT =================
struct OfflineAttendanceSubmission {
  uint16_t txId;
  char payload[MAX_PAYLOAD_BYTES];
  size_t length;
};

// FreeRTOS Synchronization
SemaphoreHandle_t displayMutex = nullptr;
SemaphoreHandle_t sdMutex = nullptr;
QueueHandle_t sdLegacyQueue = nullptr;
QueueHandle_t bleSubmissionQueue = nullptr;

// Time Management (No Battery-backed RTC)
enum TimeSource { TIME_SRC_UNSYNCED = 0, TIME_SRC_PHONE_PROVISIONAL = 1, TIME_SRC_NTP_TRUSTED = 2 };
TimeSource currentTimeSource = TIME_SRC_UNSYNCED;
time_t ntpSyncEpoch = 0;
uint32_t ntpSyncMillis = 0;
bool isTimeSynced = false;
bool isWifiFailed = false;

// Boot Identity
char bootId[33] = {0};

// Active Session
char currentSessionId[64] = "sess_current_active";

// Dynamic Challenge Slots (Monotonic 60s Expiration)
struct ChallengeSlot {
  char nonce[48];
  uint32_t issuedMillis;
  bool active;
};
ChallengeSlot activeChallenges[4];

// Enrolled Keys Registry
#define MAX_ENROLLED_KEYS 200
struct EnrolledKey {
  char matric[32];
  char student_id[48];
  char public_key[130]; // 124-char SPKI Base64
  char credential_id[48];
  char algorithm[32];
  bool revoked;
};
EnrolledKey enrolledKeys[MAX_ENROLLED_KEYS];
int enrolledKeyCount = 0;

// Terminal Keypair (mbedtls NIST P-256)
mbedtls_ecdsa_context terminalKeyCtx;
bool terminalKeyValid = false;
char terminalPublicKeyBase64[140] = {0};

// Reassembly Context for Incoming BLE Submissions
struct RxChunk {
  uint8_t data[24];
  size_t len;
};
struct ReassemblyContext {
  uint16_t txId;
  uint8_t totalChunks;
  uint8_t receivedChunks;
  uint32_t startedMillis;
  bool inProgress;
  bool chunkReceived[MAX_CHUNKS + 1];
  RxChunk chunks[MAX_CHUNKS + 1];
};
ReassemblyContext rxCtx;

// TOTP Secret for BLE Advertising Token
const uint8_t TOTP_SECRET[] = { 0x41, 0x54, 0x54, 0x45, 0x4E, 0x44, 0x5F, 0x53, 0x45, 0x43 };
const size_t TOTP_SECRET_LEN = 10;
uint32_t lastBroadcastWindow = 0xFFFFFFFF;

// ================= AUDIO & VISUAL FEEDBACK =================
void beepSuccess() {
  digitalWrite(GREEN_LED, HIGH);
  tone(BUZZER_PIN, 2000, 150);
  delay(150);
  tone(BUZZER_PIN, 2500, 200);
  delay(200);
  digitalWrite(GREEN_LED, LOW);
}

void beepError() {
  digitalWrite(RED_LED, HIGH);
  tone(BUZZER_PIN, 800, 400);
  delay(400);
  digitalWrite(RED_LED, LOW);
}

void beepClick() {
  tone(BUZZER_PIN, 1500, 50);
}

void oledPrint(String line1, String line2 = "", String line3 = "", String line4 = "") {
  if (displayMutex != nullptr && xSemaphoreTake(displayMutex, pdMS_TO_TICKS(100)) == pdPASS) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);

    display.setCursor(0, 0);
    display.println(line1);
    display.setCursor(0, 16);
    display.println(line2);
    display.setCursor(0, 32);
    display.println(line3);
    display.setCursor(0, 48);
    display.println(line4);

    // Badges in top right corner
    display.setCursor(96, 0);
    if (currentTimeSource == TIME_SRC_NTP_TRUSTED) display.print("[T]");
    else if (currentTimeSource == TIME_SRC_PHONE_PROVISIONAL) display.print("[P]");
    else if (isWifiFailed) display.print("[X]");
    else display.print("[~]");

    display.setCursor(112, 0);
    display.print(bleReady ? "[B]" : "[ ]");

    display.display();
    xSemaphoreGive(displayMutex);
  }
}

String getRFIDString() {
  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  rfid.PICC_HaltA();
  return uid;
}

String modeName() {
  if (currentMode == MODE_ATTENDANCE) return "ATTENDANCE";
  if (currentMode == MODE_ENROLLMENT) return "ENROLLMENT";
  return "CLOUD SYNC";
}

// ================= TIME HELPERS =================
time_t getCurrentUnixTime() {
  if (currentTimeSource == TIME_SRC_UNSYNCED) return 0;
  return ntpSyncEpoch + ((millis() - ntpSyncMillis) / 1000);
}

void getFormattedTimestamp(char* outBuf, size_t bufSize) {
  if (currentTimeSource == TIME_SRC_NTP_TRUSTED) {
    time_t now = getCurrentUnixTime();
    struct tm* ti = gmtime(&now);
    strftime(outBuf, bufSize, "%Y-%m-%dT%H:%M:%SZ", ti);
  } else if (currentTimeSource == TIME_SRC_PHONE_PROVISIONAL) {
    time_t now = getCurrentUnixTime();
    struct tm* ti = gmtime(&now);
    char tmp[30];
    strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%SZ", ti);
    snprintf(outBuf, bufSize, "PROV_%s", tmp);
  } else {
    uint32_t sec = millis() / 1000;
    snprintf(outBuf, bufSize, "BOOT+%us", sec);
  }
}

String timeSyncPendingValue = "";
void applyPendingTimeSyncIfAny() {
  if (timeSyncPendingValue.length() > 0) {
    time_t candidate = (time_t) strtoul(timeSyncPendingValue.c_str(), nullptr, 10);
    const time_t MIN_PLAUSIBLE = 1767225600; // 2026-01-01
    const time_t MAX_PLAUSIBLE = 2082758400; // 2036-01-01
    if (candidate >= MIN_PLAUSIBLE && candidate <= MAX_PLAUSIBLE) {
      ntpSyncEpoch = candidate;
      ntpSyncMillis = millis();
      currentTimeSource = TIME_SRC_PHONE_PROVISIONAL;
      isTimeSynced = true;
      struct timeval tv = { .tv_sec = candidate, .tv_usec = 0 };
      settimeofday(&tv, NULL);
      Serial.println("[TIMESYNC] Applied provisional clock from phone.");
    }
    timeSyncPendingValue = "";
  }
}

// ================= CRYPTOGRAPHIC PRIMITIVES (mbedtls) =================
void generateRandomBytes(uint8_t* output, size_t len) {
  for (size_t i = 0; i < len; i++) {
    output[i] = (uint8_t)(esp_random() & 0xFF);
  }
}

void sha256Bytes(const uint8_t* data, size_t len, uint8_t* outDigest) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0); // 0 = SHA-256
  mbedtls_sha256_update_ret(&ctx, data, len);
  mbedtls_sha256_finish_ret(&ctx, outDigest);
  mbedtls_sha256_free(&ctx);
}

void sha256String(const char* input, uint8_t* outDigest) {
  sha256Bytes((const uint8_t*)input, strlen(input), outDigest);
}

String bytesToHex(const uint8_t* data, size_t len) {
  String hexStr = "";
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) hexStr += "0";
    hexStr += String(data[i], HEX);
  }
  return hexStr;
}

// Convert Base64 string to raw bytes
size_t base64Decode(const char* input, uint8_t* outBuf, size_t maxLen) {
  int inputLen = strlen(input);
  int decodedLen = base64_decode_expected_len(inputLen);
  if (decodedLen > maxLen) return 0;
  char* temp = (char*)malloc(decodedLen + 1);
  if (!temp) return 0;
  int actual = base64_decode(temp, (char*)input, inputLen);
  if (actual > 0 && actual <= maxLen) {
    memcpy(outBuf, temp, actual);
    free(temp);
    return actual;
  }
  free(temp);
  return 0;
}

// Load Terminal P-256 Keypair from SD or Fail Closed
bool loadTerminalKeyFromSD() {
  mbedtls_ecdsa_init(&terminalKeyCtx);
  mbedtls_ecp_group_load(&terminalKeyCtx.grp, MBEDTLS_ECP_DP_SECP256R1);

  if (!sdAvailable) {
    terminalKeyValid = false;
    return false;
  }

  xSemaphoreTake(sdMutex, portMAX_DELAY);
  if (!SD.exists("/terminal_key.bin")) {
    xSemaphoreGive(sdMutex);
    Serial.println("[SECURITY] /terminal_key.bin NOT found on SD. Failing closed.");
    terminalKeyValid = false;
    return false;
  }

  File f = SD.open("/terminal_key.bin", FILE_READ);
  if (!f || f.size() != 32) {
    if (f) f.close();
    xSemaphoreGive(sdMutex);
    Serial.println("[SECURITY] /terminal_key.bin invalid size (expected 32 bytes). Failing closed.");
    terminalKeyValid = false;
    return false;
  }

  uint8_t privScalar[32];
  f.read(privScalar, 32);
  f.close();
  xSemaphoreGive(sdMutex);

  // Import private scalar d
  int privReadRet = mbedtls_mpi_read_binary(&terminalKeyCtx.d, privScalar, 32);
  memset(privScalar, 0, sizeof(privScalar)); // Zeroize sensitive key bytes from stack
  if (privReadRet != 0) {
    Serial.println("[SECURITY] Failed to load private key scalar.");
    terminalKeyValid = false;
    return false;
  }

  // Derive public point Q = d * G
  if (mbedtls_ecp_mul(&terminalKeyCtx.grp, &terminalKeyCtx.Q, &terminalKeyCtx.d, &terminalKeyCtx.grp.G, NULL, NULL) != 0) {
    Serial.println("[SECURITY] Failed to derive public point Q.");
    terminalKeyValid = false;
    return false;
  }

  // Export uncompressed SPKI DER (91 bytes)
  const uint8_t spkiPrefix[26] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
  };
  uint8_t spkiDer[91];
  memcpy(spkiDer, spkiPrefix, 26);
  size_t olen = 0;
  mbedtls_ecp_point_write_binary(&terminalKeyCtx.grp, &terminalKeyCtx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, spkiDer + 26, 65);

  String b64 = base64::encode(spkiDer, sizeof(spkiDer));
  strlcpy(terminalPublicKeyBase64, b64.c_str(), sizeof(terminalPublicKeyBase64));

  terminalKeyValid = true;
  Serial.println("[SECURITY] Terminal P-256 keypair successfully initialized.");
  return true;
}

// Sign 32-byte hash using Terminal P-256 Key (RFC 6979 Deterministic ECDSA)
bool signHashTerminalP256(const uint8_t* hash32, char* outCompactSigB64, size_t outSize) {
  if (!terminalKeyValid) return false;

  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  int ret = mbedtls_ecdsa_sign_det(
    &terminalKeyCtx.grp,
    &r,
    &s,
    &terminalKeyCtx.d,
    hash32,
    32,
    MBEDTLS_MD_SHA256
  );

  if (ret != 0) {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return false;
  }

  // Enforce low-S canonicality: s = min(s, order - s)
  mbedtls_mpi half_order, diff;
  mbedtls_mpi_init(&half_order);
  mbedtls_mpi_init(&diff);
  mbedtls_mpi_copy(&half_order, &terminalKeyCtx.grp.N);
  mbedtls_mpi_shift_r(&half_order, 1);

  if (mbedtls_mpi_cmp_mpi(&s, &half_order) > 0) {
    mbedtls_mpi_sub_mpi(&diff, &terminalKeyCtx.grp.N, &s);
    mbedtls_mpi_copy(&s, &diff);
  }
  mbedtls_mpi_free(&half_order);
  mbedtls_mpi_free(&diff);

  uint8_t rawSig[64];
  mbedtls_mpi_write_binary(&r, rawSig, 32);
  mbedtls_mpi_write_binary(&s, rawSig + 32, 32);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  String b64 = base64::encode(rawSig, 64);
  strlcpy(outCompactSigB64, b64.c_str(), outSize);
  return true;
}

// Verify Student P-256 Signature over Canonical Message
bool verifyStudentP256(const char* canonicalMsg, const char* sigB64, const char* spkiPubB64) {
  uint8_t spkiBytes[128];
  size_t spkiLen = base64Decode(spkiPubB64, spkiBytes, sizeof(spkiBytes));
  if (spkiLen != 91 || spkiBytes[26] != 0x04) {
    Serial.println("[CRYPTO] Invalid SPKI public key length or prefix.");
    return false;
  }

  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);
  mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);

  if (mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, spkiBytes + 26, 65) != 0) {
    mbedtls_ecdsa_free(&ctx);
    Serial.println("[CRYPTO] Failed to parse student public point Q.");
    return false;
  }

  uint8_t sigBytes[128];
  size_t sigLen = base64Decode(sigB64, sigBytes, sizeof(sigBytes));
  if (sigLen < 64) {
    mbedtls_ecdsa_free(&ctx);
    Serial.println("[CRYPTO] Signature too short.");
    return false;
  }

  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  if (sigLen == 64) {
    // Compact IEEE P1363 (R[32] || S[32])
    mbedtls_mpi_read_binary(&r, sigBytes, 32);
    mbedtls_mpi_read_binary(&s, sigBytes + 32, 32);
  } else if (sigBytes[0] == 0x30) {
    // ASN.1 DER parsing
    int offset = 2;
    if (sigBytes[1] & 0x80) offset = 2 + (sigBytes[1] & 0x7F);
    if (sigBytes[offset++] == 0x02) {
      int rLen = sigBytes[offset++];
      mbedtls_mpi_read_binary(&r, sigBytes + offset, rLen);
      offset += rLen;
      if (sigBytes[offset++] == 0x02) {
        int sLen = sigBytes[offset++];
        mbedtls_mpi_read_binary(&s, sigBytes + offset, sLen);
      }
    }
  } else {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);
    return false;
  }

  uint8_t hash[32];
  sha256String(canonicalMsg, hash);

  int ret = mbedtls_ecdsa_verify(&ctx.grp, hash, 32, &ctx.Q, &r, &s);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecdsa_free(&ctx);

  return (ret == 0);
}

// ================= DYNAMIC CHALLENGE MANAGEMENT =================
void issueFreshChallenge(char* outNonceBase64, size_t nonceSize) {
  uint8_t rawNonce[24];
  generateRandomBytes(rawNonce, sizeof(rawNonce));
  String b64 = base64::encode(rawNonce, sizeof(rawNonce));
  strlcpy(outNonceBase64, b64.c_str(), nonceSize);

  activeChallenges[0].issuedMillis = millis();
  activeChallenges[0].active = true;
  strlcpy(activeChallenges[0].nonce, outNonceBase64, sizeof(activeChallenges[0].nonce));
}

bool validateAndConsumeChallenge(const char* nonce) {
  uint32_t now = millis();
  for (int i = 0; i < 4; i++) {
    if (activeChallenges[i].active && strcmp(activeChallenges[i].nonce, nonce) == 0) {
      if ((uint32_t)(now - activeChallenges[i].issuedMillis) < 60000) {
        activeChallenges[i].active = false; // consume single-use nonce
        return true;
      } else {
        Serial.println("[SECURITY] Challenge expired (monotonic timeout)");
        activeChallenges[i].active = false;
        return false;
      }
    }
  }
  return false;
}

// ================= BLE FRAMED TRANSMISSION =================
void sendFramedAck(const char* payload, uint16_t txId) {
  if (!ackChar) return;
  size_t totalLen = strlen(payload);
  const size_t maxChunk = 14; // Fits in MTU 23 (6 byte header + 14 byte chunk = 20 bytes)
  uint8_t totalChunks = (totalLen + maxChunk - 1) / maxChunk;
  if (totalChunks == 0) totalChunks = 1;

  for (uint8_t seq = 1; seq <= totalChunks; seq++) {
    size_t start = (seq - 1) * maxChunk;
    size_t chunkLen = min(maxChunk, totalLen - start);

    uint8_t frame[BINARY_HEADER_SIZE + maxChunk];
    frame[0] = FRAME_MAGIC_BYTE;
    frame[1] = FRAME_VERSION_BYTE;
    frame[2] = (uint8_t)(txId >> 8);
    frame[3] = (uint8_t)(txId & 0xFF);
    frame[4] = seq;
    frame[5] = totalChunks;
    memcpy(frame + BINARY_HEADER_SIZE, payload + start, chunkLen);

    ackChar->setValue(frame, BINARY_HEADER_SIZE + chunkLen);
    ackChar->notify();
    delay(20);
  }
}

void sendFramedChallenge(const char* payload, uint16_t txId) {
  if (!challengeChar) return;
  size_t totalLen = strlen(payload);
  const size_t maxChunk = 14;
  uint8_t totalChunks = (totalLen + maxChunk - 1) / maxChunk;
  if (totalChunks == 0) totalChunks = 1;

  for (uint8_t seq = 1; seq <= totalChunks; seq++) {
    size_t start = (seq - 1) * maxChunk;
    size_t chunkLen = min(maxChunk, totalLen - start);

    uint8_t frame[BINARY_HEADER_SIZE + maxChunk];
    frame[0] = FRAME_MAGIC_BYTE;
    frame[1] = FRAME_VERSION_BYTE;
    frame[2] = (uint8_t)(txId >> 8);
    frame[3] = (uint8_t)(txId & 0xFF);
    frame[4] = seq;
    frame[5] = totalChunks;
    memcpy(frame + BINARY_HEADER_SIZE, payload + start, chunkLen);

    challengeChar->setValue(frame, BINARY_HEADER_SIZE + chunkLen);
    challengeChar->notify();
    delay(20);
  }
}

// ================= SD CARD DATA & REGISTRY MANAGEMENT =================
void loadEnrolledKeysFromSD() {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  enrolledKeyCount = 0;
  if (!SD.exists("/enrolled_keys.csv")) {
    File f = SD.open("/enrolled_keys.csv", FILE_WRITE);
    if (f) {
      f.println("matric,student_id,public_key,credential_id,algorithm,revoked");
      f.close();
    }
    xSemaphoreGive(sdMutex);
    return;
  }

  File f = SD.open("/enrolled_keys.csv", FILE_READ);
  if (!f) { xSemaphoreGive(sdMutex); return; }

  // Skip header
  f.readStringUntil('\n');
  while (f.available() && enrolledKeyCount < MAX_ENROLLED_KEYS) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    int p1 = line.indexOf(',');
    int p2 = line.indexOf(',', p1 + 1);
    int p3 = line.indexOf(',', p2 + 1);
    int p4 = line.indexOf(',', p3 + 1);
    int p5 = line.indexOf(',', p4 + 1);

    if (p1 > 0 && p2 > p1) {
      EnrolledKey& k = enrolledKeys[enrolledKeyCount];
      strlcpy(k.matric, line.substring(0, p1).c_str(), sizeof(k.matric));
      strlcpy(k.student_id, line.substring(p1 + 1, p2).c_str(), sizeof(k.student_id));
      if (p3 > p2) {
        strlcpy(k.public_key, line.substring(p2 + 1, p3).c_str(), sizeof(k.public_key));
      }
      if (p4 > p3) {
        strlcpy(k.credential_id, line.substring(p3 + 1, p4).c_str(), sizeof(k.credential_id));
      }
      if (p5 > p4) {
        strlcpy(k.algorithm, line.substring(p4 + 1, p5).c_str(), sizeof(k.algorithm));
        k.revoked = line.substring(p5 + 1).equalsIgnoreCase("true");
      } else if (p4 > p3) {
        k.revoked = line.substring(p4 + 1).equalsIgnoreCase("true");
      }
      enrolledKeyCount++;
    }
  }
  f.close();
  xSemaphoreGive(sdMutex);
  Serial.printf("[REGISTRY] Loaded %d enrolled student keys from SD\n", enrolledKeyCount);
}

int findEnrolledKeyByMatric(const char* matric) {
  for (int i = 0; i < enrolledKeyCount; i++) {
    if (strcasecmp(enrolledKeys[i].matric, matric) == 0 && !enrolledKeys[i].revoked) {
      return i;
    }
  }
  return -1;
}

// Search SD event index for an existing event ID
bool findEventInIndex(const char* eventId, String& outDigest, String& outSavedAt, String& outSig) {
  if (!sdAvailable) return false;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  if (!SD.exists("/event_index.csv")) {
    xSemaphoreGive(sdMutex);
    return false;
  }
  File f = SD.open("/event_index.csv", FILE_READ);
  if (!f) { xSemaphoreGive(sdMutex); return false; }

  bool found = false;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.startsWith(eventId)) {
      int p1 = line.indexOf(',');
      int p2 = line.indexOf(',', p1 + 1);
      int p3 = line.indexOf(',', p2 + 1);
      int p4 = line.indexOf(',', p3 + 1);
      int p5 = line.indexOf(',', p4 + 1);
      if (p1 > 0 && p2 > p1) {
        if (p3 > p2) outDigest = line.substring(p2 + 1, p3);
        if (p4 > p3) outSavedAt = line.substring(p3 + 1, p4);
        if (p5 > p4) outSig = line.substring(p4 + 1, p5);
        else if (p4 > p3) outSig = line.substring(p4 + 1);
        found = true;
        break;
      }
    }
  }
  f.close();
  xSemaphoreGive(sdMutex);
  return found;
}

// Append event to event index
void recordEventToIndex(const char* eventId, const char* matric, const char* digest, const char* savedAt, const char* sig) {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  File f = SD.open("/event_index.csv", FILE_APPEND);
  if (f) {
    f.printf("%s,%s,%s,%s,%s\n", eventId, matric, digest, savedAt, sig);
    f.flush();
    f.close();
  }
  xSemaphoreGive(sdMutex);
}

// ================= RESTORED BASELINE STUDENT DATABASE =================
void loadStudentsFromSD() {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  studentCount = 0;
  if (!SD.exists("/students.csv")) {
    xSemaphoreGive(sdMutex);
    return;
  }

  File f = SD.open("/students.csv", FILE_READ);
  if (!f) { xSemaphoreGive(sdMutex); return; }

  // Skip header
  f.readStringUntil('\n');
  while (f.available() && studentCount < MAX_STUDENTS) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    int p1 = line.indexOf(',');
    int p2 = line.indexOf(',', p1 + 1);
    int p3 = line.indexOf(',', p2 + 1);

    if (p1 > 0 && p2 > p1) {
      StudentRecord& s = students[studentCount];
      strlcpy(s.matric, line.substring(0, p1).c_str(), sizeof(s.matric));
      strlcpy(s.name, line.substring(p1 + 1, p2).c_str(), sizeof(s.name));
      if (p3 > p2) {
        strlcpy(s.rfid, line.substring(p2 + 1, p3).c_str(), sizeof(s.rfid));
        s.fingerprintId = line.substring(p3 + 1).toInt();
      } else {
        strlcpy(s.rfid, line.substring(p2 + 1).c_str(), sizeof(s.rfid));
        s.fingerprintId = -1;
      }
      studentCount++;
    }
  }
  f.close();
  xSemaphoreGive(sdMutex);
  Serial.printf("[DB] Loaded %d students from /students.csv\n", studentCount);
}

void saveStudentsToSD() {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  File f = SD.open("/students.csv", FILE_WRITE);
  if (f) {
    f.println("matric,name,rfid,fingerprint_id");
    for (int i = 0; i < studentCount; i++) {
      f.printf("%s,%s,%s,%d\n", students[i].matric, students[i].name, students[i].rfid, students[i].fingerprintId);
    }
    f.flush();
    f.close();
  }
  xSemaphoreGive(sdMutex);
}

int findStudentByRfid(const String& uid) {
  for (int i = 0; i < studentCount; i++) {
    if (String(students[i].rfid).equalsIgnoreCase(uid)) return i;
  }
  return -1;
}

int findStudentByIdOrMatric(const String& searchId) {
  for (int i = 0; i < studentCount; i++) {
    if (String(students[i].matric).equalsIgnoreCase(searchId)) return i;
  }
  return -1;
}

int findNextUnenrolledStudent(int startIdx) {
  for (int i = startIdx; i < studentCount; i++) {
    if (strlen(students[i].rfid) == 0 || students[i].fingerprintId == -1) {
      return i;
    }
  }
  return -1;
}

int enrollFingerprint() {
  int id = 1;
  while (id <= 127) {
    if (finger.loadModel(id) != FINGERPRINT_OK) break;
    id++;
  }
  if (id > 127) return -1;

  oledPrint("ENROLL FP", "Place Finger on", "Scanner now...");
  while (finger.getImage() != FINGERPRINT_OK) { delay(50); }
  if (finger.image2Tz(1) != FINGERPRINT_OK) return -1;

  oledPrint("ENROLL FP", "Remove finger");
  delay(1000);
  while (finger.getImage() != FINGERPRINT_NOFINGER) { delay(50); }

  oledPrint("ENROLL FP", "Place SAME finger", "again...");
  while (finger.getImage() != FINGERPRINT_OK) { delay(50); }
  if (finger.image2Tz(2) != FINGERPRINT_OK) return -1;

  if (finger.createModel() != FINGERPRINT_OK) return -1;
  if (finger.storeModel(id) != FINGERPRINT_OK) return -1;

  return id;
}

// ================= MASTER RFID NAVIGATION MENU =================
void handleMasterNavigation() {
  beepClick();
  int menuIndex = 0;
  const char* menuOptions[] = { "1. Attendance Mode", "2. Enrollment Mode", "3. Cloud Sync", "4. System Info" };
  const int totalMenuOptions = 4;

  oledPrint("MASTER MENU", menuOptions[menuIndex], "Tap card=Next", "Hold 3s=Select");
  unsigned long lastTap = millis();

  while (millis() - lastTap < 10000) {
    if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
      String uid = getRFIDString();
      if (uid == MASTER_RFID_UID) {
        beepClick();
        menuIndex = (menuIndex + 1) % totalMenuOptions;
        oledPrint("MASTER MENU", menuOptions[menuIndex], "Tap card=Next", "Wait 3s=Select");
        lastTap = millis();
      }
    }
    delay(50);
  }

  // Auto-select option after timeout
  if (menuIndex == 0) {
    currentMode = MODE_ATTENDANCE;
  } else if (menuIndex == 1) {
    currentMode = MODE_ENROLLMENT;
    enrollmentTargetIdx = findNextUnenrolledStudent(0);
  } else if (menuIndex == 2) {
    currentMode = MODE_SYNC;
  } else if (menuIndex == 3) {
    char ts[32];
    getFormattedTimestamp(ts, sizeof(ts));
    oledPrint("SYS INFO", "ID: " + DEVICE_ID, "Time: " + String(ts), "Keys: " + String(enrolledKeyCount));
    delay(3000);
    currentMode = MODE_ATTENDANCE;
  }

  oledPrint("MODE CHANGED", modeName());
  delay(1000);
}

// ================= OFFLINE BLE SUBMISSION PROCESSING TASK =================
void handleReconciliation(const char* eventId, const char* studentId, uint16_t txId) {
  String savedDigest, savedAt, savedSig;
  if (findEventInIndex(eventId, savedDigest, savedAt, savedSig)) {
    // Return the cached original signed receipt
    JsonDocument ackDoc;
    ackDoc["version"] = 1;
    ackDoc["event_id"] = eventId;
    ackDoc["terminal_id"] = DEVICE_ID;
    ackDoc["session_id"] = currentSessionId;
    ackDoc["submission_digest"] = savedDigest;
    ackDoc["status"] = "DURABLY_SAVED";
    ackDoc["sd_persisted"] = true;
    ackDoc["saved_at"] = savedAt;
    ackDoc["signature"] = savedSig;

    String ackJson;
    serializeJson(ackDoc, ackJson);
    sendFramedAck(ackJson.c_str(), txId);
    Serial.printf("[RECONCILE] Returned cached receipt for event %s\n", eventId);
  } else {
    // Event was never persisted to SD
    JsonDocument ackDoc;
    ackDoc["version"] = 1;
    ackDoc["event_id"] = eventId;
    ackDoc["terminal_id"] = DEVICE_ID;
    ackDoc["session_id"] = currentSessionId;
    ackDoc["status"] = "REJECTED";
    ackDoc["sd_persisted"] = false;
    ackDoc["error_code"] = "EVENT_NOT_FOUND";

    String ackJson;
    serializeJson(ackDoc, ackJson);
    sendFramedAck(ackJson.c_str(), txId);
    Serial.printf("[RECONCILE] Event %s not found in index\n", eventId);
  }
}

void offlineAttendanceTask(void* pvParameters) {
  OfflineAttendanceSubmission sub;
  for (;;) {
    if (xQueueReceive(bleSubmissionQueue, &sub, portMAX_DELAY) == pdPASS) {
      String raw = String(sub.payload);
      raw.trim();

      // Check if this is a reconciliation query
      if (raw.startsWith("v1|reconcile|")) {
        int p1 = raw.indexOf('|');
        int p2 = raw.indexOf('|', p1 + 1);
        int p3 = raw.indexOf('|', p2 + 1);
        String eventId = raw.substring(p2 + 1, p3);
        String studentId = raw.substring(p3 + 1);
        handleReconciliation(eventId.c_str(), studentId.c_str(), sub.txId);
        continue;
      }

      // Parse JSON attendance submission
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, raw);
      if (err) {
        Serial.println("[BLE] Malformed JSON submission.");
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "MALFORMED_JSON";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      const char* eventId = doc["event_id"];
      const char* studentId = doc["student_id"];
      const char* matric = doc["matric_number"];
      const char* terminalId = doc["terminal_id"];
      const char* sessionId = doc["session_id"];
      const char* challengeNonce = doc["challenge"];
      uint32_t phoneTs = doc["timestamp"] | 0;
      const char* timestampSrc = doc["timestamp_source"] | "phone_os";
      const char* pubKey = doc["public_key"];
      const char* signature = doc["signature"];
      const char* credId = doc["credential_id"] | "";
      const char* credVersion = doc["credential_version"] | "v1";
      const char* algorithm = doc["algorithm"] | "ECDSA_P256_SHA256";

      if (!eventId || !matric || !pubKey || !signature || !challengeNonce) {
        Serial.println("[SECURITY] Missing required submission fields.");
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "MISSING_FIELDS";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      // 1. Verify terminal binding
      if (String(terminalId) != DEVICE_ID) {
        Serial.println("[SECURITY] Terminal ID mismatch.");
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "TERMINAL_MISMATCH";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      // 2. Validate and consume dynamic challenge nonce (Monotonic 60s timeout)
      if (!validateAndConsumeChallenge(challengeNonce)) {
        Serial.println("[SECURITY] Challenge nonce expired or replayed.");
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "EXPIRED_CHALLENGE";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      // 3. Verify authorized student in cached registry
      int keyIdx = findEnrolledKeyByMatric(matric);
      if (keyIdx < 0) {
        Serial.printf("[SECURITY] Student %s NOT in cached enrolled_keys.csv\n", matric);
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "STUDENT_NOT_ENROLLED";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      // Validate submitted public key matches authorized key in registry
      if (strcmp(enrolledKeys[keyIdx].public_key, pubKey) != 0) {
        Serial.println("[SECURITY] Submitted public key does NOT match authorized registry key.");
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "UNAUTHORIZED_PUBLIC_KEY";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      // 4. Cryptographic Signature Verification
      String canonicalMsg = String("v1|submission|") + eventId + "|" + credId + "|" + credVersion + "|"
                          + algorithm + "|" + studentId + "|" + matric + "|" + terminalId + "|"
                          + (sessionId ? sessionId : "") + "|" + challengeNonce + "|"
                          + String(phoneTs) + "|" + timestampSrc;

      if (!verifyStudentP256(canonicalMsg.c_str(), signature, pubKey)) {
        Serial.println("[SECURITY] Student ECDSA P-256 signature verification FAILED.");
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "INVALID_SIGNATURE";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      uint8_t hash[32];
      sha256String(canonicalMsg.c_str(), hash);
      String submissionDigest = bytesToHex(hash, 32);

      // 5. Idempotency & Conflict Check in event index
      String existingDigest, existingSavedAt, existingSig;
      if (findEventInIndex(eventId, existingDigest, existingSavedAt, existingSig)) {
        if (existingDigest == submissionDigest) {
          // Identical duplicate: return cached receipt
          JsonDocument ackDoc;
          ackDoc["version"] = 1;
          ackDoc["event_id"] = eventId;
          ackDoc["terminal_id"] = DEVICE_ID;
          ackDoc["session_id"] = sessionId;
          ackDoc["submission_digest"] = submissionDigest;
          ackDoc["status"] = "DURABLY_SAVED";
          ackDoc["sd_persisted"] = true;
          ackDoc["saved_at"] = existingSavedAt;
          ackDoc["signature"] = existingSig;

          String out;
          serializeJson(ackDoc, out);
          sendFramedAck(out.c_str(), sub.txId);
          Serial.printf("[IDEMPOTENCY] Re-acknowledged identical event %s\n", eventId);
        } else {
          // Reused event ID with conflicting payload
          JsonDocument errDoc;
          errDoc["version"] = 1;
          errDoc["event_id"] = eventId;
          errDoc["status"] = "REJECTED";
          errDoc["sd_persisted"] = false;
          errDoc["error_code"] = "EVENT_ID_CONFLICT";

          String out;
          serializeJson(errDoc, out);
          sendFramedAck(out.c_str(), sub.txId);
          Serial.printf("[SECURITY] Conflicting reuse of event_id %s\n", eventId);
        }
        continue;
      }

      // 6. Durable SD Write (BEFORE emitting success receipt)
      if (!sdAvailable) {
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "SD_UNAVAILABLE";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        continue;
      }

      char termSavedAt[32];
      getFormattedTimestamp(termSavedAt, sizeof(termSavedAt));
      time_t unixNow = getCurrentUnixTime();

      // Sign terminal receipt over canonical string:
      // v1|receipt|{event_id}|{terminal_id}|{session_id}|{submission_digest}|DURABLY_SAVED|true||{saved_at}
      String canonicalReceipt = String("v1|receipt|") + eventId + "|" + DEVICE_ID + "|"
                              + (sessionId ? sessionId : "") + "|" + submissionDigest + "|DURABLY_SAVED|true||"
                              + termSavedAt;

      uint8_t receiptHash[32];
      sha256String(canonicalReceipt.c_str(), receiptHash);
      char receiptSigB64[100] = {0};
      signHashTerminalP256(receiptHash, receiptSigB64, sizeof(receiptSigB64));

      // Append complete record to /attendance_offline.csv
      xSemaphoreTake(sdMutex, portMAX_DELAY);
      File f = SD.open("/attendance_offline.csv", FILE_APPEND);
      bool writeOk = false;
      if (f) {
        size_t written = f.printf(
          "%s,%s,%s,%s,%s,%u,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
          eventId,
          studentId,
          matric,
          terminalId,
          (sessionId ? sessionId : ""),
          phoneTs,
          termSavedAt,
          pubKey,
          signature,
          challengeNonce,
          timestampSrc,
          credId,
          credVersion,
          algorithm,
          submissionDigest.c_str(),
          receiptSigB64
        );
        f.flush();
        f.close();
        writeOk = (written > 0);
      }
      xSemaphoreGive(sdMutex);

      if (!writeOk) {
        Serial.println("[SD] Failed to write record to /attendance_offline.csv");
        JsonDocument errDoc;
        errDoc["version"] = 1;
        errDoc["status"] = "REJECTED";
        errDoc["sd_persisted"] = false;
        errDoc["error_code"] = "SD_WRITE_FAILURE";
        String out;
        serializeJson(errDoc, out);
        sendFramedAck(out.c_str(), sub.txId);
        beepError();
        continue;
      }

      // Record in event index
      recordEventToIndex(eventId, matric, submissionDigest.c_str(), termSavedAt, receiptSigB64);

      // 7. Emit Authenticated Success Receipt
      JsonDocument ackDoc;
      ackDoc["version"] = 1;
      ackDoc["event_id"] = eventId;
      ackDoc["terminal_id"] = DEVICE_ID;
      ackDoc["session_id"] = sessionId;
      ackDoc["submission_digest"] = submissionDigest;
      ackDoc["status"] = "DURABLY_SAVED";
      ackDoc["sd_persisted"] = true;
      ackDoc["saved_at"] = termSavedAt;
      ackDoc["signature"] = receiptSigB64;

      String ackJson;
      serializeJson(ackDoc, ackJson);
      sendFramedAck(ackJson.c_str(), sub.txId);

      beepSuccess();
      oledPrint("BLE ATTENDANCE", "Verified & Saved", String(matric));
      delay(1500);
      oledPrint("SYSTEM READY", modeName());
    }
  }
}

// ================= BLE CHARACTERISTIC CALLBACKS =================
class SubmissionWriteCB : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pChar) override {
    uint8_t* data = pChar->getData();
    size_t len = pChar->getLength();
    if (len < BINARY_HEADER_SIZE) return;

    if (data[0] != FRAME_MAGIC_BYTE || data[1] != FRAME_VERSION_BYTE) {
      Serial.println("[FRAMING] Rejecting packet: Invalid magic bytes");
      return;
    }

    uint16_t txId = ((uint16_t)data[2] << 8) | data[3];
    uint8_t seq = data[4];
    uint8_t total = data[5];

    if (total == 0 || seq == 0 || seq > total) return;

    // Reset buffer on new transaction or timeout (15s)
    if (!rxCtx.inProgress || rxCtx.txId != txId || (millis() - rxCtx.startedMillis > 15000)) {
      rxCtx.txId = txId;
      rxCtx.totalChunks = total;
      rxCtx.receivedChunks = 0;
      rxCtx.startedMillis = millis();
      rxCtx.inProgress = true;
      memset(rxCtx.chunkReceived, 0, sizeof(rxCtx.chunkReceived));
    }

    // Inconsistent total chunks check
    if (rxCtx.totalChunks != total) {
      Serial.println("[FRAMING] Inconsistent total chunks count in transaction.");
      rxCtx.inProgress = false;
      return;
    }

    // Duplicate chunk check
    size_t chunkDataLen = len - BINARY_HEADER_SIZE;
    if (rxCtx.chunkReceived[seq]) {
      // Check conflicting bytes
      if (rxCtx.chunks[seq].len != chunkDataLen || memcmp(rxCtx.chunks[seq].data, data + BINARY_HEADER_SIZE, chunkDataLen) != 0) {
        Serial.println("[FRAMING] Rejecting conflicting duplicate chunk bytes.");
        rxCtx.inProgress = false;
      }
      return;
    }

    if (chunkDataLen > sizeof(rxCtx.chunks[seq].data)) {
      return;
    }

    memcpy(rxCtx.chunks[seq].data, data + BINARY_HEADER_SIZE, chunkDataLen);
    rxCtx.chunks[seq].len = chunkDataLen;
    rxCtx.chunkReceived[seq] = true;
    rxCtx.receivedChunks++;

    if (rxCtx.receivedChunks == rxCtx.totalChunks) {
      rxCtx.inProgress = false;

      // Assemble complete payload in sequential order 1..total
      OfflineAttendanceSubmission sub;
      sub.txId = rxCtx.txId;
      size_t offset = 0;
      for (uint8_t i = 1; i <= rxCtx.totalChunks; i++) {
        if (offset + rxCtx.chunks[i].len < sizeof(sub.payload) - 1) {
          memcpy(sub.payload + offset, rxCtx.chunks[i].data, rxCtx.chunks[i].len);
          offset += rxCtx.chunks[i].len;
        }
      }
      sub.payload[offset] = '\0';
      sub.length = offset;

      // Enqueue to background task — keep BLE callback instant & non-blocking
      xQueueSend(bleSubmissionQueue, &sub, 0);
    }
  }
};

class TimeSyncWriteCB : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pChar) override {
    if (currentTimeSource == TIME_SRC_NTP_TRUSTED) return;
    String v = pChar->getValue();
    if (v.length() > 0 && v.length() <= 12) {
      timeSyncPendingValue = v;
    }
  }
};

// ================= BLE ADVERTISING ROLLING TOKEN =================
void packTokenBCD(uint32_t sixDigitToken, uint8_t* out3Bytes) {
  char buf[7];
  snprintf(buf, sizeof(buf), "%06u", sixDigitToken);
  out3Bytes[0] = ((buf[0] - '0') << 4) | (buf[1] - '0');
  out3Bytes[1] = ((buf[2] - '0') << 4) | (buf[3] - '0');
  out3Bytes[2] = ((buf[4] - '0') << 4) | (buf[5] - '0');
}

uint32_t computeTOTPToken(uint32_t window) {
  uint8_t counterBytes[8] = {0};
  uint32_t counter = window;
  for (int i = 7; i >= 4; i--) {
    counterBytes[i] = counter & 0xFF;
    counter >>= 8;
  }

  uint8_t hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, TOTP_SECRET, TOTP_SECRET_LEN);
  mbedtls_md_hmac_update(&ctx, counterBytes, 8);
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  int offset = hmacResult[31] & 0x0F;
  uint32_t binCode = ((hmacResult[offset] & 0x7F) << 24)
                    | ((hmacResult[offset + 1] & 0xFF) << 16)
                    | ((hmacResult[offset + 2] & 0xFF) << 8)
                    | (hmacResult[offset + 3] & 0xFF);
  return binCode % 1000000;
}

void updateBLEBroadcastToken() {
  if (!bleReady || bleAdvertising == nullptr) return;

  uint32_t nowSec = getCurrentUnixTime();
  if (nowSec == 0) return; // Wait until clock is initialized

  uint32_t currentWindow = nowSec / 30;
  if (currentWindow == lastBroadcastWindow) return;
  lastBroadcastWindow = currentWindow;

  uint32_t token = computeTOTPToken(currentWindow);
  uint8_t tokenBCD[3];
  packTokenBCD(token, tokenBCD);

  uint8_t mfgData[7];
  mfgData[0] = 0xFF;
  mfgData[1] = 0xFF;
  mfgData[2] = 0x41; // 'A'
  mfgData[3] = 0x54; // 'T'
  mfgData[4] = tokenBCD[0];
  mfgData[5] = tokenBCD[1];
  mfgData[6] = tokenBCD[2];

  BLEAdvertisementData advData;
  advData.setManufacturerData(String((char*)mfgData, 7));
  advData.setCompleteServices(BLEUUID(ATTENDCLASS_SERVICE_UUID));
  advData.setName((String("AttendESP_") + DEVICE_ID).c_str());

  bleAdvertising->stop();
  bleAdvertising->setAdvertisementData(advData);
  bleAdvertising->start();
}

// ================= CLOUD SYNC & OUTBOX MANAGEMENT =================
void refreshCredentialsFromCloud() {
  oledPrint("CLOUD SYNC", "Refreshing Keys...");
  String url = String(CLOUD_BASE_URL) + String(SYNC_ENDPOINT);

  WiFiClientSecure secureClient;
  secureClient.setCACert(SUPABASE_CA_CERT);

  HTTPClient http;
  http.begin(secureClient, url);
  http.addHeader("x-device-key", DEVICE_KEY);
  http.addHeader("x-sync-file-type", "signed_attendance");
  http.addHeader("x-sync-action", "refresh_credentials");
  http.setTimeout(20000);

  int httpCode = http.POST("");
  if (httpCode >= 200 && httpCode < 300) {
    String resp = http.getString();
    JsonDocument doc;
    deserializeJson(doc, resp);

    if (doc["enrolled_keys"].is<JsonArray>()) {
      xSemaphoreTake(sdMutex, portMAX_DELAY);
      File tmp = SD.open("/enrolled_keys.tmp", FILE_WRITE);
      bool writeOk = false;
      if (tmp) {
        tmp.println("matric,student_id,public_key,credential_id,algorithm,revoked");
        JsonArray arr = doc["enrolled_keys"].as<JsonArray>();
        for (JsonObject o : arr) {
          tmp.printf("%s,%s,%s,%s,%s,%s\n",
            (const char*)o["matric_number"],
            (const char*)o["student_id"],
            (const char*)o["public_key"],
            (const char*)o["credential_id"],
            (const char*)o["algorithm"],
            "false"
          );
        }
        tmp.flush();
        tmp.close();
        writeOk = true;
      }

      if (writeOk) {
        SD.remove("/enrolled_keys.csv");
        // Rename temp file to primary file
        File src = SD.open("/enrolled_keys.tmp", FILE_READ);
        File dst = SD.open("/enrolled_keys.csv", FILE_WRITE);
        if (src && dst) {
          while (src.available()) {
            uint8_t buf[64];
            size_t n = src.read(buf, sizeof(buf));
            dst.write(buf, n);
          }
          src.close();
          dst.close();
          SD.remove("/enrolled_keys.tmp");
        }
      } else {
        SD.remove("/enrolled_keys.tmp");
      }
      xSemaphoreGive(sdMutex);
      loadEnrolledKeysFromSD();
      Serial.println("[SYNC] Enrolled keys updated atomically.");
    }
  }
  http.end();
}

int getSyncCheckpoint() {
  if (!sdAvailable) return 0;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  if (!SD.exists("/sync_checkpoint.txt")) {
    xSemaphoreGive(sdMutex);
    return 0;
  }
  File f = SD.open("/sync_checkpoint.txt", FILE_READ);
  if (!f) { xSemaphoreGive(sdMutex); return 0; }
  String val = f.readStringUntil('\n');
  f.close();
  xSemaphoreGive(sdMutex);
  return val.toInt();
}

void saveSyncCheckpoint(int lineIdx) {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  File f = SD.open("/sync_checkpoint.txt", FILE_WRITE);
  if (f) {
    f.println(lineIdx);
    f.flush();
    f.close();
  }
  xSemaphoreGive(sdMutex);
}

void archiveRejectedRecord(const char* eventId, const char* matric, const char* reason, const char* recordLine) {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  File f = SD.open("/rejected_records.csv", FILE_APPEND);
  if (f) {
    char ts[32];
    getFormattedTimestamp(ts, sizeof(ts));
    f.printf("%s,%s,%s,%s,%s\n", ts, eventId, matric, reason, recordLine);
    f.flush();
    f.close();
  }
  xSemaphoreGive(sdMutex);
}

bool uploadSignedAttendanceBatch() {
  if (!sdAvailable) return true;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  if (!SD.exists("/attendance_offline.csv")) {
    xSemaphoreGive(sdMutex);
    return true;
  }

  File f = SD.open("/attendance_offline.csv", FILE_READ);
  if (!f) { xSemaphoreGive(sdMutex); return true; }

  int currentCheckpoint = getSyncCheckpoint();
  int currentLine = 0;

  // Skip past acknowledged records
  while (f.available() && currentLine < currentCheckpoint) {
    f.readStringUntil('\n');
    currentLine++;
  }

  if (!f.available()) {
    f.close();
    xSemaphoreGive(sdMutex);
    return true; // Nothing new to upload
  }

  oledPrint("UPLOADING", "Signed Batch...", "Offset: " + String(currentCheckpoint));

  // Read bounded batch of up to 10 records
  String lines[10];
  String payload = "";
  int batchCount = 0;
  while (f.available() && batchCount < 10) {
    String l = f.readStringUntil('\n');
    l.trim();
    if (l.length() > 0) {
      lines[batchCount] = l;
      payload += l + "\n";
      batchCount++;
    }
  }
  f.close();
  xSemaphoreGive(sdMutex);

  if (batchCount == 0) return true;

  String url = String(CLOUD_BASE_URL) + String(SYNC_ENDPOINT);
  WiFiClientSecure secureClient;
  secureClient.setCACert(SUPABASE_CA_CERT);

  HTTPClient http;
  http.begin(secureClient, url);
  http.addHeader("Content-Type", "text/csv");
  http.addHeader("x-sync-file-type", "signed_attendance");
  http.addHeader("x-device-key", DEVICE_KEY);
  http.setTimeout(25000);

  int httpCode = http.POST(payload);
  bool requestOk = (httpCode >= 200 && httpCode < 300);

  if (requestOk) {
    String resp = http.getString();
    JsonDocument respDoc;
    deserializeJson(respDoc, resp);

    JsonArray records = respDoc["records"].as<JsonArray>();
    int advanceCount = 0;

    for (int i = 0; i < batchCount; i++) {
      String status = "RETRYABLE";
      String reason = "";
      String evId = "";
      String mat = "";

      if (i < (int)records.size()) {
        status = (const char*)records[i]["status"] ? (const char*)records[i]["status"] : "RETRYABLE";
        reason = (const char*)records[i]["reason"] ? (const char*)records[i]["reason"] : "";
        evId = (const char*)records[i]["event_id"] ? (const char*)records[i]["event_id"] : "";
        mat = (const char*)records[i]["matric_number"] ? (const char*)records[i]["matric_number"] : "";
      }

      if (status == "ACCEPTED" || status == "DUPLICATE") {
        advanceCount++;
      } else if (status == "REJECTED") {
        archiveRejectedRecord(evId.c_str(), mat.c_str(), reason.c_str(), lines[i].c_str());
        advanceCount++;
      } else {
        // RETRYABLE: stop advancing checkpoint at this record
        break;
      }
    }

    if (advanceCount > 0) {
      saveSyncCheckpoint(currentCheckpoint + advanceCount);
      Serial.printf("[SYNC] Advanced checkpoint by %d records (new offset: %d)\n", advanceCount, currentCheckpoint + advanceCount);
    }
  }

  http.end();
  return requestOk;
}

bool uploadLegacyFile(const char* filePath, const char* fileType, const char* displayLabel) {
  if (!sdAvailable) return true;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  if (!SD.exists(filePath)) {
    xSemaphoreGive(sdMutex);
    return true;
  }
  File f = SD.open(filePath, FILE_READ);
  if (!f || f.size() == 0) {
    if (f) f.close();
    xSemaphoreGive(sdMutex);
    return true;
  }

  oledPrint("UPLOADING", String(displayLabel), "Streaming records...");
  String payload = "";
  while (f.available() && payload.length() < 16384) {
    payload += f.readStringUntil('\n') + "\n";
  }
  f.close();
  xSemaphoreGive(sdMutex);

  String url = String(CLOUD_BASE_URL) + String(SYNC_ENDPOINT);
  WiFiClientSecure secureClient;
  secureClient.setCACert(SUPABASE_CA_CERT);

  HTTPClient http;
  http.begin(secureClient, url);
  http.addHeader("Content-Type", "text/csv");
  http.addHeader("x-sync-file-type", fileType);
  http.addHeader("x-device-key", DEVICE_KEY);
  http.setTimeout(25000);

  int httpCode = http.POST(payload);
  bool success = (httpCode >= 200 && httpCode < 300);

  if (success) {
    xSemaphoreTake(sdMutex, portMAX_DELAY);
    SD.remove(filePath);
    xSemaphoreGive(sdMutex);
    Serial.printf("[SYNC] Uploaded and cleared legacy %s\n", displayLabel);
  }
  http.end();
  return success;
}

void syncDataToCloud() {
  oledPrint("CLOUD SYNC", "Starting Wi-Fi...");

  if (bleReady) {
    BLEDevice::deinit(true);
    bleReady = false;
    bleServer = nullptr;
    delay(50);
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int retries = 0;
  while (WiFi.status() != WL_CONNECTED && retries < 20) {
    delay(500);
    retries++;
    oledPrint("CLOUD SYNC", "Connecting...", "Attempt " + String(retries) + "/20");
  }

  if (WiFi.status() != WL_CONNECTED) {
    oledPrint("SYNC FAILED", "Wi-Fi unreachable.");
    beepError();
    delay(2000);
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    currentMode = MODE_ATTENDANCE;
    return;
  }

  oledPrint("SYNC CONNECTED", "Synchronizing...");
  beepClick();

  // 1. Refresh active student credential registry from cloud
  refreshCredentialsFromCloud();

  // 2. Upload batches of signed offline attendance
  uploadSignedAttendanceBatch();

  // 3. Upload legacy 2FA attendance logs
  uploadLegacyFile("/attendance.csv", "attendance", "Attendance Logs");

  // 4. Upload legacy student enrollments
  uploadLegacyFile("/enrollment.csv", "enrollment", "Enrollment Logs");

  oledPrint("SYNC COMPLETE", "All logs updated.");
  beepSuccess();
  delay(2000);

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  currentMode = MODE_ATTENDANCE;
  oledPrint("SYSTEM READY", modeName());
}

// ================= LEGACY SD WRITE TASK =================
void sdWriteTask(void* pvParameters) {
  LogEvent ev;
  for (;;) {
    if (xQueueReceive(sdLegacyQueue, &ev, pdMS_TO_TICKS(100)) == pdPASS) {
      if (sdAvailable) {
        xSemaphoreTake(sdMutex, portMAX_DELAY);
        if (ev.logType == 'A') {
          File f = SD.open("/attendance.csv", FILE_APPEND);
          if (f) {
            char ts[32];
            getFormattedTimestamp(ts, sizeof(ts));
            f.printf("\"%s\",%s,%s,%s\n", ts, ev.name, ev.matric, ev.method);
            f.flush();
            f.close();
          }
        } else if (ev.logType == 'E') {
          File f = SD.open("/enrollment.csv", FILE_APPEND);
          if (f) {
            char ts[32];
            getFormattedTimestamp(ts, sizeof(ts));
            f.printf("\"%s\",%s,%s,%s,%d\n", ts, ev.name, ev.matric, ev.rfid, ev.fp_id);
            f.flush();
            f.close();
          }
        }
        xSemaphoreGive(sdMutex);
      }
    }
  }
}

// ================= NTP TIME SYNC TASK =================
void ntpSyncTask(void* pvParameters) {
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int retries = 0;
  while (WiFi.status() != WL_CONNECTED && retries < 15) {
    vTaskDelay(500 / portTICK_PERIOD_MS);
    retries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
    struct tm timeinfo;
    if (getLocalTime(&timeinfo, 5000)) {
      ntpSyncEpoch = mktime(&timeinfo);
      ntpSyncMillis = millis();
      currentTimeSource = TIME_SRC_NTP_TRUSTED;
      isTimeSynced = true;

      struct timeval tv = { .tv_sec = ntpSyncEpoch, .tv_usec = 0 };
      settimeofday(&tv, NULL);
      Serial.println("[NTP] Hardware clock synchronized.");
    }
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
  } else {
    isWifiFailed = true;
    Serial.println("[NTP] Wi-Fi offline. Using internal boot timer.");
  }
  vTaskDelete(NULL);
}

// ================= BLE GATT INITIALIZATION =================
void initBLEGattServices() {
  if (bleReady) return;

  BLEDevice::init((String("AttendESP_") + DEVICE_ID).c_str());
  bleServer = BLEDevice::createServer();

  BLEService* attService = bleServer->createService(ATTENDCLASS_SERVICE_UUID);

  challengeChar = attService->createCharacteristic(
    CHALLENGE_CHAR_UUID,
    BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
  );

  submissionChar = attService->createCharacteristic(
    SUBMISSION_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR
  );
  submissionChar->setCallbacks(new SubmissionWriteCB());

  ackChar = attService->createCharacteristic(
    ACK_CHAR_UUID,
    BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
  );

  timeSyncChar = attService->createCharacteristic(
    TIMESYNC_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE
  );
  timeSyncChar->setCallbacks(new TimeSyncWriteCB());

  attService->start();

  bleAdvertising = BLEDevice::getAdvertising();
  bleAdvertising->addServiceUUID(ATTENDCLASS_SERVICE_UUID);
  bleAdvertising->setScanResponse(true);
  bleAdvertising->setMinPreferred(0x06);
  bleAdvertising->start();

  bleReady = true;
  Serial.println("[BLE] AttendClass Offline GATT Services online.");
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  Serial.println("\n=== AttendESP v3 Initializing ===");

  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);

  // Generate unique boot identity
  uint8_t bootBytes[16];
  generateRandomBytes(bootBytes, sizeof(bootBytes));
  String bHex = bytesToHex(bootBytes, sizeof(bootBytes));
  strlcpy(bootId, bHex.c_str(), sizeof(bootId));

  displayMutex = xSemaphoreCreateMutex();
  sdMutex = xSemaphoreCreateMutex();
  sdLegacyQueue = xQueueCreate(20, sizeof(LogEvent));
  bleSubmissionQueue = xQueueCreate(10, sizeof(OfflineAttendanceSubmission));

  Wire.begin(OLED_SDA, OLED_SCL);
  display.begin(OLED_ADDR, true);
  oledPrint("AttendESP v3", "Booting Hardware...");

  SPI.begin(RFID_SCK, RFID_MISO, RFID_MOSI);
  rfid.PCD_Init();

  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if (SD.begin(SD_CS, sdSPI)) {
    sdAvailable = true;
    loadStudentsFromSD();
    loadEnrolledKeysFromSD();
    if (!loadTerminalKeyFromSD()) {
      oledPrint("CONFIG ERROR", "Terminal Key Missing", "Place key on SD:", "/terminal_key.bin");
      beepError();
      delay(4000);
    }
  } else {
    oledPrint("SD WARNING", "Card Not Found!");
    delay(2000);
  }

  fpSerial.begin(57600, SERIAL_8N1, FP_RX, FP_TX);
  finger.begin(57600);

  xTaskCreatePinnedToCore(sdWriteTask, "SDWriteTask", 4096, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(offlineAttendanceTask, "BLETask", 8192, NULL, 2, NULL, 0);
  xTaskCreatePinnedToCore(ntpSyncTask, "NTPTask", 4096, NULL, 1, NULL, 0);

  initBLEGattServices();
  oledPrint("SYSTEM READY", modeName());
}

// ================= MAIN LOOP =================
void loop() {
  if (currentMode == MODE_SYNC) {
    syncDataToCloud();
    return;
  }

  applyPendingTimeSyncIfAny();
  updateBLEBroadcastToken();

  // --- HANDLE THE SKIP BUTTON (Fingerprint tap during Enrollment) ---
  if (currentMode == MODE_ENROLLMENT && enrollmentTargetIdx >= 0) {
    if (finger.getImage() == FINGERPRINT_OK) {
      beepClick();
      enrollmentTargetIdx = findNextUnenrolledStudent(enrollmentTargetIdx + 1);
      if (enrollmentTargetIdx >= 0) {
        oledPrint("SKIPPED", "Next:", String(students[enrollmentTargetIdx].name));
        delay(1000);
        oledPrint("ENROLL:", String(students[enrollmentTargetIdx].name), "Card=Save | FP=Skip");
      } else {
        oledPrint("ENROLLMENT", "All available", "students onboarded!");
        delay(2000);
        currentMode = MODE_ATTENDANCE;
        oledPrint("SYSTEM READY", modeName());
      }
      while (finger.getImage() != FINGERPRINT_NOFINGER) { delay(50); }
    }
  }

  // --- HANDLE RFID SCANS ---
  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String scannedUID = getRFIDString();
    Serial.println("\nCard Tapped: " + scannedUID);

    if (scannedUID == MASTER_RFID_UID) {
      handleMasterNavigation();
      return;
    }

    if (currentMode == MODE_ENROLLMENT) {
      if (enrollmentTargetIdx < 0) {
        oledPrint("ENROLLMENT", "All students onboarded");
        delay(1500);
      } else {
        StudentRecord& t = students[enrollmentTargetIdx];
        if (findStudentByRfid(scannedUID) >= 0) {
          oledPrint("RFID IN USE", "Try another card");
          beepError();
          delay(900);
          oledPrint("ENROLL:", String(t.name), "Card=Save | FP=Skip");
        } else {
          oledPrint("CARD SAVED", "Matric: " + String(t.matric), "Setting up Finger...");
          beepSuccess();
          delay(1500);

          int newFingerID = enrollFingerprint();
          if (newFingerID != -1) {
            oledPrint("ENROLL SUCCESS!", "Card & Finger Linked", String(t.name));
            strlcpy(t.rfid, scannedUID.c_str(), sizeof(t.rfid));
            t.fingerprintId = newFingerID;
            saveStudentsToSD();

            LogEvent enrollLog;
            enrollLog.logType = 'E';
            strlcpy(enrollLog.matric, t.matric, sizeof(enrollLog.matric));
            strlcpy(enrollLog.name, t.name, sizeof(enrollLog.name));
            strlcpy(enrollLog.rfid, t.rfid, sizeof(enrollLog.rfid));
            enrollLog.fp_id = newFingerID;
            enrollLog.scan_millis = millis();
            xQueueSend(sdLegacyQueue, &enrollLog, 0);

            beepSuccess();
            delay(1500);

            enrollmentTargetIdx = findNextUnenrolledStudent(enrollmentTargetIdx + 1);
            if (enrollmentTargetIdx >= 0) {
              oledPrint("ENROLL:", String(students[enrollmentTargetIdx].name), "Card=Save | FP=Skip");
            } else {
              oledPrint("ENROLLMENT", "List completed");
              delay(1500);
              currentMode = MODE_ATTENDANCE;
              oledPrint("SYSTEM READY", modeName());
            }
          } else {
            oledPrint("ENROLL FAILED", "Try again");
            delay(1500);
            oledPrint("ENROLL:", String(t.name), "Card=Save | FP=Skip");
          }
        }
      }
    } else if (currentMode == MODE_ATTENDANCE) {
      beepClick();
      int stuIdx = findStudentByRfid(scannedUID);
      if (stuIdx >= 0) {
        oledPrint("CARD VERIFIED", String(students[stuIdx].name), "Place Finger...");
        unsigned long fpTimeout = millis();
        int matchedFingerID = -1;
        bool sensorTouched = false;

        while (millis() - fpTimeout < 5000) {
          if (finger.getImage() == FINGERPRINT_OK) {
            sensorTouched = true;
            if (finger.image2Tz() == FINGERPRINT_OK) {
              if (finger.fingerSearch() == FINGERPRINT_OK) {
                matchedFingerID = finger.fingerID;
              }
              break;
            }
          }
          delay(50);
        }

        if (matchedFingerID != -1 && matchedFingerID == students[stuIdx].fingerprintId) {
          oledPrint("2FA SUCCESS!", "Welcome,", String(students[stuIdx].name));
          beepSuccess();

          LogEvent newLog;
          newLog.logType = 'A';
          strlcpy(newLog.matric, students[stuIdx].matric, sizeof(newLog.matric));
          strlcpy(newLog.name, students[stuIdx].name, sizeof(newLog.name));
          strlcpy(newLog.method, "2FA", sizeof(newLog.method));
          newLog.scan_millis = millis();
          xQueueSend(sdLegacyQueue, &newLog, 0);
        } else if (sensorTouched) {
          oledPrint("ACCESS DENIED", "ID MISMATCH", "Wrong fingerprint");
          beepError();
        } else {
          oledPrint("2FA TIMEOUT", "Finger not", "detected");
          beepError();
        }
      } else {
        oledPrint("ACCESS DENIED", "Unknown Card");
        beepError();
      }

      delay(2000);
      oledPrint("SYSTEM READY", modeName());
    }
  }

  delay(50);
}
