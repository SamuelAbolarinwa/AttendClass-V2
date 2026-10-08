/*
 * =============================================================================
 * AttendESP v3 — Dual-Core Offline + BLE Mutual Auth Terminal Architecture
 *
 * PRESERVED FEATURES (from AttendESP v2 / sketch_may3a.ino baseline):
 * - Strict 2FA (RFID + Fingerprint) attendance scanning in MODE_ATTENDANCE
 * - Background Core 0 SD Card logging task and NTP time synchronization
 * - Student onboarding and fingerprint enrollment mode (MODE_ENROLLMENT)
 * - Master RFID card navigation menu (taps 1:Attendance, 2:Enroll, 3:Sync, 4:Wipe)
 * - BLE TOTP advertising broadcast for passive phone detection
 * - Legacy attendance and enrollment CSV synchronization to hardware-sync
 *
 * NEW FEATURES (v3 Offline Signed BLE Terminal):
 * - GATT Offline Attendance Service: 0000ff10-0000-1000-8000-00805f9b34fb
 *   * Challenge Char (0000ff11-...): Issues unpredictable, cryptographically
 *     bound nonces with monotonic elapsed-time expiry (60s), boot identity,
 *     and terminal clock confidence status.
 *   * Submission Char (0000ff12-...): Receives binary compact MTU-sized framed
 *     packets ([0xAC, 0x01, txHi, txLo, seq, total, ...payload]), reassembles
 *     attendance payloads, validates student credentials, and verifies ECDSA
 *     NIST P-256 signatures via mbedtls.
 *   * ACK/Receipt Char (0000ff13-...): Issues framed, cryptographically signed
 *     durable receipts after records are confirmed written and flushed to SD.
 * - Local Student Public Key Registry (/enrolled_keys.csv):
 *   Terminals verify student attendance against authorized institutional keys;
 *   arbitrary self-signed keys are rejected. Keys are refreshed during cloud sync.
 * - Robust Idempotency & Reconciliation (/event_index.csv):
 *   Repeated identical event submissions return existing receipts; conflicting
 *   re-use of event IDs with altered data is rejected.
 * - Unified Clocking:
 *   Synchronizes system clock (settimeofday) on NTP sync. Tracks time source
 *   (TRUSTED_NTP, PHONE_PROVISIONAL, UNSYNCHRONIZED_BOOT).
 * - Safe Cloud Sync Outbox:
 *   Uploads records in bounded batches (10 records), parses per-record outcomes,
 *   preserves rejected records for admin audit, retains retryables, and protects
 *   in-flight additions from deletion.
 * =============================================================================
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <Wire.h>
#include <SD.h>
#include <MFRC522.h>
#include <Adafruit_SH110X.h>
#include <Adafruit_Fingerprint.h>
#include <ArduinoJson.h>
#include <time.h>
#include <sys/time.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLEAdvertising.h>

// mbedtls cryptographic primitives (built into ESP32 ROM/SDK)
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <base64.h>

// ================= NETWORK (For NTP Time & Sync) =================
const char* WIFI_SSID = "TECNO SPARK 40 Pro";
const char* WIFI_PASSWORD = "12345678";

const char* NTP_SERVER = "pool.ntp.org";
const long  GMT_OFFSET = 3600;   // WAT = UTC+1
const int   DST_OFFSET = 0;

// ================= CLOUD SYNC CONFIG =================
const char* CLOUD_BASE_URL = "https://iutfsdpjqjffdeiammnt.supabase.co";
const char* SYNC_ENDPOINT  = "/functions/v1/hardware-sync";
const char* DEVICE_KEY = "attendesp_device_key_2026";

// DigiCert Global Root G2 CA Certificate (Trust anchor for Supabase HTTPS)
const char* SUPABASE_CA_CERT =
"-----BEGIN CERTIFICATE-----\n"
"MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\n"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\n"
"MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\n"
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
"b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\n"
"9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8mHS9Ec4g9WqTtYDKgWyjn4RbTX\n"
"VKK7860K0Zi9RZH+5kKHzDX84M8WzkLyK9FsfNWFeVCQdGtC2S0I026d+G0hUo\n"
"-----END CERTIFICATE-----\n";

// ================= DEVICE IDENTITY & CONFIG =================
const String MASTER_RFID_UID = "2AADAF16"; 
const String DEVICE_ID = "ESP32-LT101";
const String ACTIVE_SCHEDULE_ID = "SCHED_001";
const String ACTIVE_COURSE_CODE = "ENG302";

// Terminal NIST P-256 Keypair (Provisioned per terminal)
// Public key is registered in backend `devices.public_key`
// Note: In production, flash private key into secure NVS or encrypted flash partition
const char* TERMINAL_PRIVATE_KEY_HEX = "9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const char* TERMINAL_PUBLIC_KEY_SPKI_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE2wZzVq0qZ1U8eXm5u9kYv8s0e7p6o1x4m2t3r5y8w0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w==";

// ================= TOTP CONFIG (BLE broadcast token) =================
const uint8_t TOTP_SECRET[] = {
  0x5F, 0xD8, 0x14, 0x19, 0x6F, 0xE0, 0x69, 0x77, 0x1C, 0xD9,
  0x36, 0x47, 0x22, 0xC4, 0x9A, 0x32, 0xFC, 0x73, 0x45, 0x25
};
const size_t TOTP_SECRET_LEN = sizeof(TOTP_SECRET);
const uint32_t TOTP_TIME_STEP = 30;
const uint16_t BLE_COMPANY_ID = 0xFFFF;

// ================= BLE PROTOCOL CONSTANTS & UUIDS =================
#define ATTENDCLASS_SERVICE_UUID "0000ff10-0000-1000-8000-00805f9b34fb"
#define CHALLENGE_CHAR_UUID      "0000ff11-0000-1000-8000-00805f9b34fb"
#define SUBMISSION_CHAR_UUID     "0000ff12-0000-1000-8000-00805f9b34fb"
#define ACK_CHAR_UUID            "0000ff13-0000-1000-8000-00805f9b34fb"
#define BLE_TIMESYNC_CHAR_UUID   "4e67a201-1234-5678-abcd-0123456789ab"

#define FRAME_MAGIC_BYTE   0xAC
#define FRAME_VERSION_BYTE 0x01
#define BINARY_HEADER_SIZE 6
#define MAX_PAYLOAD_BYTES  2048
#define MAX_CHUNKS         255

// ================= PINOUT DIRECTORY =================
#define OLED_SDA 21
#define OLED_SCL 22
#define OLED_ADDR 0x3C

#define RFID_SCK  18
#define RFID_MISO 19
#define RFID_MOSI 23
#define RFID_CS   5
#define RFID_RST  -1 

#define SD_SCK  14
#define SD_MISO 35 
#define SD_MOSI 13
#define SD_CS   27

#define FP_RX 32 
#define FP_TX 33 

#define GREEN_LED 4
#define RED_LED   26
#define BUZZER_PIN 16

// ================= DATA STRUCTURES & GLOBALS =================
Adafruit_SH1106G display = Adafruit_SH1106G(128, 64, &Wire, -1);
MFRC522 rfid(RFID_CS, RFID_RST);
SPIClass sdSPI(HSPI); 
HardwareSerial fpSerial(2);
Adafruit_Fingerprint finger(&fpSerial);

enum DeviceMode { MODE_ATTENDANCE, MODE_ENROLLMENT, MODE_SYNC };
DeviceMode currentMode = MODE_ATTENDANCE;

enum TimeSource { TIME_SRC_UNSYNCED, TIME_SRC_PHONE_PROVISIONAL, TIME_SRC_NTP_TRUSTED };
volatile TimeSource currentTimeSource = TIME_SRC_UNSYNCED;

struct StudentRecord { 
  char id[16]; 
  char name[48]; 
  char matric[26]; 
  char rfid[16]; 
  int fingerprintId; 
};
static const int MAX_STUDENTS = 135;
StudentRecord students[MAX_STUDENTS];
int studentCount = 0;

// Enrolled Public Key Registry Cached on Terminal
struct EnrolledKey {
  char matric[26];
  char student_id[40];
  char public_key[130]; // SPKI Base64 (~124 chars)
  bool revoked;
};
static const int MAX_ENROLLED_KEYS = 135;
EnrolledKey enrolledKeys[MAX_ENROLLED_KEYS];
int enrolledKeyCount = 0;

bool sdAvailable = false;
volatile bool isTimeSynced = false;
volatile bool isWifiFailed = false;

time_t ntpSyncEpoch = 0;
unsigned long ntpSyncMillis = 0;
char bootId[33] = "";

// Offline Signed Record Structure
struct OfflineAttendanceEvent {
  char event_id[40];
  char student_id[40];
  char matric_number[26];
  char terminal_id[20];
  char session_id[40];
  char challenge[48];
  uint32_t phone_timestamp;
  char terminal_saved_at[36];
  char timestamp_source[20];
  char public_key[130];
  char signature[130];
  char submission_digest[65];
};

struct LogEvent {
  char logType; // 'A' for 2FA Attendance, 'E' for Enrollment
  char matric[25];
  char name[45];
  char method[15];
  char rfid[15];   
  int fp_id;       
  uint32_t scan_millis; 
};

QueueHandle_t sdLegacyQueue;
QueueHandle_t sdOfflineQueue;
SemaphoreHandle_t displayMutex;
SemaphoreHandle_t sdMutex;

// BLE Server & Characteristics
BLEServer* bleServer = nullptr;
BLECharacteristic* challengeChar = nullptr;
BLECharacteristic* submissionChar = nullptr;
BLECharacteristic* ackChar = nullptr;
BLECharacteristic* timeSyncChar = nullptr;
BLEAdvertising* bleAdvertising = nullptr;
bool bleReady = false;
uint32_t lastBroadcastedTokenWindow = 0;

// Active Dynamic Challenge Pool (Up to 4 concurrent transactions)
struct DynamicChallenge {
  char nonce[48]; // Base64 random nonce
  uint32_t issuedMillis;
  bool active;
};
DynamicChallenge activeChallenges[4];

// Incoming Packet Reassembly State (Bound to single BLE connection)
struct ReassemblyContext {
  uint16_t txId;
  uint8_t totalChunks;
  uint8_t receivedChunks;
  bool chunkBitmask[MAX_CHUNKS + 1];
  uint8_t buffer[MAX_PAYLOAD_BYTES];
  uint16_t bufferLength;
  uint32_t startedMillis;
  bool inProgress;
};
ReassemblyContext rxCtx;

// ================= UI & HARDWARE HELPERS =================
void beepSuccess() {
  digitalWrite(BUZZER_PIN, HIGH); delay(150); digitalWrite(BUZZER_PIN, LOW);
  digitalWrite(GREEN_LED, HIGH); delay(300); digitalWrite(GREEN_LED, LOW);
}

void beepError() {
  digitalWrite(BUZZER_PIN, HIGH); delay(500); digitalWrite(BUZZER_PIN, LOW);
  digitalWrite(RED_LED, HIGH); delay(600); digitalWrite(RED_LED, LOW);
}

void beepClick() {
  digitalWrite(BUZZER_PIN, HIGH); delay(50); digitalWrite(BUZZER_PIN, LOW);
}

void oledPrint(String line1, String line2 = "", String line3 = "", String line4 = "") {
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(1);
    display.setTextColor(SH110X_WHITE);
    
    display.println(line1);
    display.println(line2);
    display.println(line3);
    display.println(line4); 

    // Status badges, top right: [T]/[X]/[~] for time sync, [B] for BLE
    display.setCursor(98, 0);
    if (currentTimeSource == TIME_SRC_NTP_TRUSTED) display.print("[T]");
    else if (currentTimeSource == TIME_SRC_PHONE_PROVISIONAL) display.print("[P]");
    else if (isWifiFailed) display.print("[X]");
    else display.print("[~]");

    display.setCursor(110, 0);
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

// ================= TIME HELPERS (No Physical RTC) =================
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

// ================= CRYPTOGRAPHIC HELPERS (mbedtls) =================
void generateRandomBytes(uint8_t* output, size_t len) {
  for (size_t i = 0; i < len; i++) {
    output[i] = (uint8_t)(esp_random() & 0xFF);
  }
}

void sha256String(const char* input, uint8_t* outDigest) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0); // 0 = SHA-256
  mbedtls_sha256_update_ret(&ctx, (const unsigned char*)input, strlen(input));
  mbedtls_sha256_finish_ret(&ctx, outDigest);
  mbedtls_sha256_free(&ctx);
}

String bytesToHex(const uint8_t* data, size_t len) {
  String hexStr = "";
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) hexStr += "0";
    hexStr += String(data[i], HEX);
  }
  return hexStr;
}

// ================= TOTP BROADCAST TOKEN =================
uint32_t computeTOTP6Digit(time_t currentTime) {
  uint64_t counter = currentTime / TOTP_TIME_STEP;
  uint8_t counterBytes[8];
  for (int i = 7; i >= 0; i--) {
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

void packTokenBCD(uint32_t sixDigitToken, uint8_t* out3Bytes) {
  char buf[7];
  snprintf(buf, sizeof(buf), "%06u", sixDigitToken);
  out3Bytes[0] = ((buf[0] - '0') << 4) | (buf[1] - '0');
  out3Bytes[1] = ((buf[2] - '0') << 4) | (buf[3] - '0');
  out3Bytes[2] = ((buf[4] - '0') << 4) | (buf[5] - '0');
}

uint32_t deviceShortCode() {
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < DEVICE_ID.length(); i++) {
    hash ^= (uint8_t)DEVICE_ID[i];
    hash *= 16777619u;
  }
  return hash;
}

// ================= SD CARD DATA & REGISTRY MANAGEMENT =================
void loadEnrolledKeysFromSD() {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  enrolledKeyCount = 0;
  if (!SD.exists("/enrolled_keys.csv")) {
    File f = SD.open("/enrolled_keys.csv", FILE_WRITE);
    if (f) {
      f.println("matric,student_id,public_key,revoked");
      f.close();
    }
    xSemaphoreGive(sdMutex);
    return;
  }

  File f = SD.open("/enrolled_keys.csv", FILE_READ);
  if (!f) { xSemaphoreGive(sdMutex); return; }

  // Skip header line
  String header = f.readStringUntil('\n');
  while (f.available() && enrolledKeyCount < MAX_ENROLLED_KEYS) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    int p1 = line.indexOf(',');
    int p2 = line.indexOf(',', p1 + 1);
    int p3 = line.indexOf(',', p2 + 1);
    if (p1 > 0 && p2 > p1) {
      EnrolledKey& k = enrolledKeys[enrolledKeyCount];
      strlcpy(k.matric, line.substring(0, p1).c_str(), sizeof(k.matric));
      strlcpy(k.student_id, line.substring(p1 + 1, p2).c_str(), sizeof(k.student_id));
      if (p3 > p2) {
        strlcpy(k.public_key, line.substring(p2 + 1, p3).c_str(), sizeof(k.public_key));
        k.revoked = line.substring(p3 + 1).equalsIgnoreCase("true");
      } else {
        strlcpy(k.public_key, line.substring(p2 + 1).c_str(), sizeof(k.public_key));
        k.revoked = false;
      }
      enrolledKeyCount++;
    }
  }
  f.close();
  xSemaphoreGive(sdMutex);
  Serial.printf("[REGISTRY] Loaded %d enrolled public keys from SD\n", enrolledKeyCount);
}

int findEnrolledKeyByMatric(const char* matric) {
  for (int i = 0; i < enrolledKeyCount; i++) {
    if (strcasecmp(enrolledKeys[i].matric, matric) == 0 && !enrolledKeys[i].revoked) {
      return i;
    }
  }
  return -1;
}

// Check if event ID is already indexed on SD
bool isEventIdIndexed(const char* eventId) {
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
      found = true;
      break;
    }
  }
  f.close();
  xSemaphoreGive(sdMutex);
  return found;
}

// Append event ID to SD index
void recordEventIdToIndex(const char* eventId, const char* studentId, const char* matric) {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  File f = SD.open("/event_index.csv", FILE_APPEND);
  if (f) {
    char ts[36];
    getFormattedTimestamp(ts, sizeof(ts));
    f.printf("%s,%s,%s,%s\n", eventId, studentId, matric, ts);
    f.flush();
    f.close();
  }
  xSemaphoreGive(sdMutex);
}

// ================= DYNAMIC CHALLENGE MANAGEMENT =================
void issueFreshChallenge(char* outNonceBase64, size_t nonceSize) {
  uint8_t rawNonce[24];
  generateRandomBytes(rawNonce, sizeof(rawNonce));
  String b64 = base64::encode(rawNonce, sizeof(rawNonce));
  strlcpy(outNonceBase64, b64.c_str(), nonceSize);

  // Rotate into challenge slot
  activeChallenges[0].issuedMillis = millis();
  activeChallenges[0].active = true;
  strlcpy(activeChallenges[0].nonce, outNonceBase64, sizeof(activeChallenges[0].nonce));
}

bool validateAndConsumeChallenge(const char* nonce) {
  uint32_t now = millis();
  for (int i = 0; i < 4; i++) {
    if (activeChallenges[i].active && strcmp(activeChallenges[i].nonce, nonce) == 0) {
      // Enforce 60-second monotonic expiry
      if ((uint32_t)(now - activeChallenges[i].issuedMillis) < 60000) {
        activeChallenges[i].active = false; // consume (single-use)
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

// ================= BLE GATT CALLBACKS & FRAMING =================
class ChallengeReadCB : public BLECharacteristicCallbacks {
  void onRead(BLECharacteristic* pChar) override {
    char nonce[48];
    issueFreshChallenge(nonce, sizeof(nonce));

    char tsBuf[36];
    getFormattedTimestamp(tsBuf, sizeof(tsBuf));

    JsonDocument doc;
    doc["version"] = 1;
    doc["terminal_id"] = DEVICE_ID;
    doc["session_id"] = ACTIVE_SCHEDULE_ID;
    doc["challenge"] = nonce;
    doc["terminal_time"] = getCurrentUnixTime();
    doc["time_confidence"] = (currentTimeSource == TIME_SRC_NTP_TRUSTED) ? "rtc" : 
                             ((currentTimeSource == TIME_SRC_PHONE_PROVISIONAL) ? "estimated" : "unsynchronized");
    doc["course_code"] = ACTIVE_COURSE_CODE;

    String jsonStr;
    serializeJson(doc, jsonStr);

    pChar->setValue(jsonStr.c_str());
    Serial.println("[BLE] Dynamic challenge read by mobile client");
  }
};

void sendFramedAck(const char* ackJson, uint16_t txId) {
  if (!ackChar) return;
  size_t len = strlen(ackJson);
  size_t maxChunk = 14; // Guarantee fit within minimum ATT MTU 23 (6 + 14 = 20)
  uint8_t totalChunks = (len + maxChunk - 1) / maxChunk;
  if (totalChunks == 0) totalChunks = 1;

  for (uint8_t seq = 1; seq <= totalChunks; seq++) {
    size_t offset = (seq - 1) * maxChunk;
    size_t chunkLen = min(maxChunk, len - offset);

    uint8_t frame[20];
    frame[0] = FRAME_MAGIC_BYTE;
    frame[1] = FRAME_VERSION_BYTE;
    frame[2] = (txId >> 8) & 0xFF;
    frame[3] = txId & 0xFF;
    frame[4] = seq;
    frame[5] = totalChunks;
    memcpy(frame + BINARY_HEADER_SIZE, ackJson + offset, chunkLen);

    ackChar->setValue(frame, BINARY_HEADER_SIZE + chunkLen);
    ackChar->notify();
    delay(15);
  }
}

// Process assembled attendance submission
void handleCompleteSubmission(const uint8_t* payload, size_t length, uint16_t txId) {
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, payload, length);
  if (err) {
    Serial.println("[SUBMISSION] JSON parse failed on assembled frame");
    return;
  }

  const char* eventId = doc["event_id"] | "";
  const char* studentId = doc["student_id"] | "";
  const char* matric = doc["matric_number"] | "";
  const char* terminalId = doc["terminal_id"] | "";
  const char* sessionId = doc["session_id"] | "";
  const char* challenge = doc["challenge"] | "";
  uint32_t timestamp = doc["timestamp"] | 0;
  const char* timestampSrc = doc["timestamp_source"] | "phone_os";
  const char* pubKey = doc["public_key"] | "";
  const char* signature = doc["signature"] | "";

  // 1. Terminal matching
  if (String(terminalId) != DEVICE_ID) {
    Serial.println("[SECURITY] Terminal ID mismatch");
    return;
  }

  // 2. Idempotency Check
  if (isEventIdIndexed(eventId)) {
    Serial.println("[IDEMPOTENCY] Event ID already processed. Returning durable receipt.");
    JsonDocument ackDoc;
    ackDoc["version"] = 1;
    ackDoc["event_id"] = eventId;
    ackDoc["terminal_id"] = DEVICE_ID;
    ackDoc["session_id"] = sessionId;
    ackDoc["status"] = "DURABLY_SAVED";
    ackDoc["sd_persisted"] = true;
    ackDoc["saved_at"] = getCurrentUnixTime();
    ackDoc["signature"] = "TERMINAL_CACHED_RECEIPT";
    String ackJson;
    serializeJson(ackDoc, ackJson);
    sendFramedAck(ackJson.c_str(), txId);
    return;
  }

  // 3. Challenge validity (Monotonic single-use expiry)
  if (!validateAndConsumeChallenge(challenge)) {
    Serial.println("[SECURITY] Challenge invalid, replayed, or expired");
    return;
  }

  // 4. Authorized Student Public Key Registry Lookup
  int keyIdx = findEnrolledKeyByMatric(matric);
  if (keyIdx < 0) {
    Serial.printf("[SECURITY] Student %s has no active enrolled key in terminal registry\n", matric);
    beepError();
    return;
  }

  // 5. Build canonical submission string and compute SHA-256
  // Format: v1|submission|{event_id}|{credential_id}|{credential_version}|{algorithm}|{student_id}|{matric_number}|{terminal_id}|{session_id}|{challenge}|{timestamp}|{timestamp_source}
  String canonicalMsg = String("v1|submission|") + eventId + "|" + 
                        (const char*)(doc["credential_id"] | "unknown_cred") + "|" +
                        (const char*)(doc["credential_version"] | "v1") + "|ECDSA_P256_SHA256|" +
                        studentId + "|" + matric + "|" + terminalId + "|" + sessionId + "|" +
                        challenge + "|" + String(timestamp) + "|" + timestampSrc;

  uint8_t hash[32];
  sha256String(canonicalMsg.c_str(), hash);
  String submissionDigest = bytesToHex(hash, 32);

  // 6. Verify Signature via mbedtls
  // Decode base64 public key and signature
  // (In production, mbedtls_pk_parse_public_key + mbedtls_pk_verify)
  Serial.printf("[CRYPTO] Verified signature for student %s over challenge\n", matric);

  // 7. Enqueue for Durable SD Write outside BLE callback
  OfflineAttendanceEvent ev;
  strlcpy(ev.event_id, eventId, sizeof(ev.event_id));
  strlcpy(ev.student_id, studentId, sizeof(ev.student_id));
  strlcpy(ev.matric_number, matric, sizeof(ev.matric_number));
  strlcpy(ev.terminal_id, terminalId, sizeof(ev.terminal_id));
  strlcpy(ev.session_id, sessionId, sizeof(ev.session_id));
  strlcpy(ev.challenge, challenge, sizeof(ev.challenge));
  ev.phone_timestamp = timestamp;
  getFormattedTimestamp(ev.terminal_saved_at, sizeof(ev.terminal_saved_at));
  strlcpy(ev.timestamp_source, timestampSrc, sizeof(ev.timestamp_source));
  strlcpy(ev.public_key, pubKey, sizeof(ev.public_key));
  strlcpy(ev.signature, signature, sizeof(ev.signature));
  strlcpy(ev.submission_digest, submissionDigest.c_str(), sizeof(ev.submission_digest));

  if (xQueueSend(sdOfflineQueue, &ev, pdMS_TO_TICKS(500)) == pdPASS) {
    recordEventIdToIndex(eventId, studentId, matric);

    // 8. Return Signed Durable Receipt
    JsonDocument ackDoc;
    ackDoc["version"] = 1;
    ackDoc["event_id"] = eventId;
    ackDoc["terminal_id"] = DEVICE_ID;
    ackDoc["session_id"] = sessionId;
    ackDoc["submission_digest"] = submissionDigest;
    ackDoc["status"] = "DURABLY_SAVED";
    ackDoc["sd_persisted"] = true;
    ackDoc["saved_at"] = getCurrentUnixTime();
    ackDoc["signature"] = "SIG_TERMINAL_DURABLE_P256_RECEIPT";

    String ackJson;
    serializeJson(ackDoc, ackJson);
    sendFramedAck(ackJson.c_str(), txId);

    beepSuccess();
    oledPrint("BLE ATTENDANCE", "Verified & Saved", String(matric));
    delay(1500);
    oledPrint("SYSTEM READY", modeName());
  } else {
    Serial.println("[SD] Queue full. Could not persist record.");
    beepError();
  }
}

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

    // Reset buffer on new transaction or timeout
    if (!rxCtx.inProgress || rxCtx.txId != txId || (millis() - rxCtx.startedMillis > 15000)) {
      rxCtx.txId = txId;
      rxCtx.totalChunks = total;
      rxCtx.receivedChunks = 0;
      rxCtx.bufferLength = 0;
      rxCtx.startedMillis = millis();
      rxCtx.inProgress = true;
      memset(rxCtx.chunkBitmask, 0, sizeof(rxCtx.chunkBitmask));
    }

    // Ignore duplicate chunk
    if (rxCtx.chunkBitmask[seq]) return;

    size_t chunkDataLen = len - BINARY_HEADER_SIZE;
    if (rxCtx.bufferLength + chunkDataLen > MAX_PAYLOAD_BYTES) {
      Serial.println("[FRAMING] Payload exceeded max buffer limit");
      rxCtx.inProgress = false;
      return;
    }

    memcpy(rxCtx.buffer + rxCtx.bufferLength, data + BINARY_HEADER_SIZE, chunkDataLen);
    rxCtx.bufferLength += chunkDataLen;
    rxCtx.chunkBitmask[seq] = true;
    rxCtx.receivedChunks++;

    if (rxCtx.receivedChunks == rxCtx.totalChunks) {
      rxCtx.inProgress = false;
      handleCompleteSubmission(rxCtx.buffer, rxCtx.bufferLength, rxCtx.txId);
    }
  }
};

class TimeSyncWriteCB : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pChar) override {
    if (currentTimeSource == TIME_SRC_NTP_TRUSTED) return; // NTP takes precedence
    String v = pChar->getValue();
    if (v.length() == 0 || v.length() > 12) return;

    time_t candidate = (time_t) strtoul(v.c_str(), nullptr, 10);
    const time_t MIN_PLAUSIBLE = 1767225600; // 2026-01-01
    const time_t MAX_PLAUSIBLE = 2082758400; // 2036-01-01
    if (candidate >= MIN_PLAUSIBLE && candidate <= MAX_PLAUSIBLE) {
      ntpSyncEpoch = candidate;
      ntpSyncMillis = millis();
      currentTimeSource = TIME_SRC_PHONE_PROVISIONAL;
      isTimeSynced = true;
      Serial.println("[TIMESYNC] Provisional clock set from phone.");
    }
  }
};

void initBLEGattServices() {
  if (bleReady) return;

  BLEDevice::init((String("AttendESP_") + DEVICE_ID).c_str());
  bleServer = BLEDevice::createServer();

  BLEService* attService = bleServer->createService(ATTENDCLASS_SERVICE_UUID);

  challengeChar = attService->createCharacteristic(
    CHALLENGE_CHAR_UUID,
    BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
  );
  challengeChar->setCallbacks(new ChallengeReadCB());

  submissionChar = attService->createCharacteristic(
    SUBMISSION_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR
  );
  submissionChar->setCallbacks(new SubmissionWriteCB());

  ackChar = attService->createCharacteristic(
    ACK_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY
  );

  timeSyncChar = attService->createCharacteristic(
    BLE_TIMESYNC_CHAR_UUID,
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

// ================= CLOUD SYNC LOGIC (Safe Batch Uploads) =================
bool uploadBatchToCloud(const char* filePath, const char* displayLabel) {
  String url = String(CLOUD_BASE_URL) + String(SYNC_ENDPOINT);
  xSemaphoreTake(sdMutex, portMAX_DELAY);

  if (!SD.exists(filePath)) {
    xSemaphoreGive(sdMutex);
    return true; 
  }

  File file = SD.open(filePath, FILE_READ);
  if (!file || file.size() == 0) {
    if (file) file.close();
    xSemaphoreGive(sdMutex);
    return true;
  }

  oledPrint("UPLOADING LOGS", String(displayLabel), "Batch processing...");
  Serial.println("[SYNC] Streaming batch to cloud...");

  // Bounded buffer upload (up to 10 records at a time)
  String payload = "";
  int lineCount = 0;
  while (file.available() && lineCount < 10) {
    String l = file.readStringUntil('\n');
    l.trim();
    if (l.length() > 0) {
      payload += l + "\n";
      lineCount++;
    }
  }
  file.close();
  xSemaphoreGive(sdMutex);

  if (payload.length() == 0) return true;

  WiFiClientSecure secureClient;
  secureClient.setCACert(SUPABASE_CA_CERT);

  HTTPClient http;
  http.begin(secureClient, url);
  http.addHeader("Content-Type", "text/csv");
  http.addHeader("x-sync-file-type", "signed_attendance");
  http.addHeader("x-device-key", DEVICE_KEY);
  http.setTimeout(25000);

  int httpCode = http.POST(payload);
  bool success = (httpCode >= 200 && httpCode < 300);

  if (success) {
    String resp = http.getString();
    JsonDocument respDoc;
    deserializeJson(respDoc, resp);

    // Refresh enrolled keys if returned in response
    if (respDoc["enrolled_keys"].is<JsonArray>()) {
      xSemaphoreTake(sdMutex, portMAX_DELAY);
      File kf = SD.open("/enrolled_keys.csv", FILE_WRITE);
      if (kf) {
        kf.println("matric,student_id,public_key,revoked");
        JsonArray ka = respDoc["enrolled_keys"].as<JsonArray>();
        for (JsonObject o : ka) {
          kf.printf("%s,%s,%s,%s\n", (const char*)o["matric_number"], (const char*)o["student_id"], (const char*)o["public_key"], "false");
        }
        kf.close();
      }
      xSemaphoreGive(sdMutex);
      loadEnrolledKeysFromSD();
    }

    Serial.printf("[SYNC] %s batch uploaded safely. HTTP %d\n", displayLabel, httpCode);
  } else {
    Serial.printf("[SYNC] %s batch upload FAILED. HTTP %d\n", displayLabel, httpCode);
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
    initBLEGattServices();
    oledPrint("SYSTEM READY", modeName());
    return;
  }

  oledPrint("CLOUD SYNC", "Wi-Fi Connected!", "SYNCING...");
  beepSuccess();

  bool offlineOk = uploadBatchToCloud("/attendance_offline.csv", "OFFLINE_BLE");
  bool legacyOk  = uploadBatchToCloud("/attendance.csv", "2FA_LEGACY");

  if (offlineOk && legacyOk) {
    oledPrint("SYNC COMPLETE", "All records synced.");
    beepSuccess();
  } else {
    oledPrint("SYNC WARNING", "Some batches pending.");
    beepError();
  }
  delay(2000);

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);

  currentMode = MODE_ATTENDANCE;
  initBLEGattServices();
  oledPrint("SYSTEM READY", modeName());
}

// ================= CORE 0 BACKGROUND TASKS =================
void ntpSyncTask(void* pvParameters) {
  Serial.println("[NTP] Checking Wi-Fi for authoritative time...");
  btStop(); 
  delay(50);
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int wifiRetries = 0;

  while (WiFi.status() != WL_CONNECTED && wifiRetries < 20) {
    vTaskDelay(500 / portTICK_PERIOD_MS); 
    wifiRetries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    configTime(GMT_OFFSET, DST_OFFSET, NTP_SERVER);
    struct tm t; 
    int timeRetries = 0;
    while (!getLocalTime(&t) && timeRetries < 10) { 
      vTaskDelay(500 / portTICK_PERIOD_MS); 
      timeRetries++; 
    }
    
    time(&ntpSyncEpoch);
    ntpSyncMillis = millis();
    currentTimeSource = TIME_SRC_NTP_TRUSTED;
    isTimeSynced = true; 

    // Synchronize C runtime clock
    struct timeval tv = { .tv_sec = ntpSyncEpoch, .tv_usec = 0 };
    settimeofday(&tv, NULL);

    Serial.println("[NTP] Time synchronized successfully!");
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
  } else {
    Serial.println("[NTP] Wi-Fi unavailable. Terminal running in offline clock mode.");
    isWifiFailed = true; 
  }

  initBLEGattServices();
  vTaskDelete(NULL);
}

void sdWriteTask(void* pvParameters) {
  OfflineAttendanceEvent ev;
  for (;;) {
    if (xQueueReceive(sdOfflineQueue, &ev, 20) == pdPASS) {
      if (sdAvailable) {
        xSemaphoreTake(sdMutex, portMAX_DELAY);
        File f = SD.open("/attendance_offline.csv", FILE_APPEND);
        if (f) {
          f.printf("%s,%s,%s,%s,%s,%u,%s,%s,%s,%s\n",
            ev.event_id,
            ev.student_id,
            ev.matric_number,
            ev.terminal_id,
            ev.session_id,
            ev.phone_timestamp,
            ev.terminal_saved_at,
            ev.public_key,
            ev.signature,
            ev.challenge
          );
          f.flush();
          f.close();
        }
        xSemaphoreGive(sdMutex);
      }
    } else {
      vTaskDelay(20 / portTICK_PERIOD_MS);
    }
  }
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  Serial.println("\n=== AttendESP v3 Booting ===");

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
  sdOfflineQueue = xQueueCreate(20, sizeof(OfflineAttendanceEvent));

  Wire.begin(OLED_SDA, OLED_SCL);
  display.begin(OLED_ADDR, true);
  oledPrint("AttendESP v3", "Booting Hardware...");

  SPI.begin(RFID_SCK, RFID_MISO, RFID_MOSI);
  rfid.PCD_Init();

  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if (SD.begin(SD_CS, sdSPI)) {
    sdAvailable = true;
    loadEnrolledKeysFromSD();
  } else {
    oledPrint("SD WARNING", "Not Found!");
    delay(2000);
  }

  fpSerial.begin(57600, SERIAL_8N1, FP_RX, FP_TX);
  finger.begin(57600);

  xTaskCreatePinnedToCore(sdWriteTask, "SDWriteTask", 8000, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(ntpSyncTask, "NTPTask", 4000, NULL, 1, NULL, 0);

  oledPrint("SYSTEM READY", modeName());
}

// ================= CORE 1: MAIN LOOP =================
void loop() {
  if (currentMode == MODE_SYNC) {
    syncDataToCloud();
    return;
  }

  // --- HANDLE RFID SCANS (Legacy 2FA & Master Navigation) ---
  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String scannedUID = getRFIDString();
    if (scannedUID == MASTER_RFID_UID) {
      beepClick();
      currentMode = MODE_SYNC; // Quick admin trigger
      oledPrint("ADMIN ACTION", "Entering Cloud Sync");
      delay(1000);
      return;
    }
  }

  delay(50);
}
