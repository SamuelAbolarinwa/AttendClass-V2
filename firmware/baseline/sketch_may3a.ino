/*
 * ============================================================
 * AttendESP v2 — Dual-Core Offline + BLE Broadcast Architecture
 * Core 1: Strict 2FA (RFID+FP) + continuous BLE TOTP broadcast, UI, Enrollment, Sync
 * Core 0: Dual SD Card Logging & NTP Time Sync (Background)
 *
 * CHANGES FROM v1:
 * - BLE switched from GATT connection-based to advertising BROADCAST.
 *   The module no longer receives anything over BLE — it only
 *   broadcasts a rotating cryptographic token. Phones scan passively
 *   (no connection needed), so any number of phones can read it
 *   simultaneously. Attendance verification + logging now happens
 *   entirely SERVER-SIDE: the phone app reads the token, does its own
 *   face verification, and submits {token, student_id, rssi, timestamp}
 *   directly to the Supabase backend over its own internet connection.
 * - BLE broadcasting now runs CONCURRENTLY with RFID/FP scanning in
 *   MODE_ATTENDANCE, instead of being a separate exclusive mode. There
 *   is no more MODE_QR_BLE — it's merged into MODE_ATTENDANCE.
 * - CLOUD_BASE_URL updated to the new Supabase project. This URL is
 *   ONLY used for hardware-sync (CSV batch upload of 2FA logs) and
 *   still uses DEVICE_KEY, a separate credential from the new
 *   TOTP_SECRET below — different trust models, kept independent.
 * - Old QR-code-for-BLE-pairing flow removed (no longer needed since
 *   phones don't need a pairing target, just a scan target).
 * - Added a minimal GATT time-sync service, running ALONGSIDE the
 *   broadcast advertising (BLE can be both an advertiser and a
 *   connectable peripheral at once — no radio conflict, unlike the
 *   WiFi/BLE one). This exists purely so the device can get an
 *   accurate clock from a phone if NTP was never available, keeping
 *   the whole check-in path fully WiFi-independent. Gated: only
 *   accepts a write while isTimeSynced is false. Once synced (via NTP
 *   or a phone write), further writes are ignored, so a phone can
 *   bootstrap a clock but never override an already-good one.
 * ============================================================
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
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLEAdvertising.h>
#include <mbedtls/md.h>
#include <base64.h>

// ================= NETWORK (For NTP Time & Sync) =================
const char* WIFI_SSID = "TECNO SPARK 40 Pro";
const char* WIFI_PASSWORD = "12345678";

const char* NTP_SERVER = "pool.ntp.org";
const long  GMT_OFFSET = 3600;   // WAT = UTC+1
const int   DST_OFFSET = 0;

// ================= CLOUD SYNC CONFIG (hardware-sync, CSV batch, legacy 2FA path) =================
const char* CLOUD_BASE_URL = "https://iutfsdpjqjffdeiammnt.supabase.co";
const char* SYNC_ENDPOINT  = "/functions/v1/hardware-sync";
const char* DEVICE_KEY = "attendesp_device_key_2026"; // separate credential from TOTP_SECRET below

// ================= DEVICE & CLASS CONFIG =================
const String MASTER_RFID_UID = "2AADAF16"; 
const String DEVICE_ID = "ESP32-LT101";
const String ACTIVE_SCHEDULE_ID = "SCHED_001";
const String ACTIVE_COURSE_CODE = "ENG302";

// ================= TOTP CONFIG (BLE broadcast token) =================
// This secret must be registered server-side as this exact device's
// devices.totp_secret_encrypted (base32) in the new Supabase project.
// Generated once, provisioned to both sides — treat as sensitive.
// Base32 equivalent for the DB: L7MBIGLP4BUXOHGZGZDSFRE2GL6HGRJF
const uint8_t TOTP_SECRET[] = {
  0x5F, 0xD8, 0x14, 0x19, 0x6F, 0xE0, 0x69, 0x77, 0x1C, 0xD9,
  0x36, 0x47, 0x22, 0xC4, 0x9A, 0x32, 0xFC, 0x73, 0x45, 0x25
};
const size_t TOTP_SECRET_LEN = sizeof(TOTP_SECRET);
const uint32_t TOTP_TIME_STEP = 30; // seconds

// BLE advertising manufacturer-specific data layout (target v2 protocol):
//   bytes 0-1: company ID
//   bytes 2-5: device short-code (derived from DEVICE_ID)
//   bytes 6-8: 6-digit TOTP token, packed BCD
//
// !! 0xFFFF is a reserved "not assigned" placeholder for prototyping
// ONLY. It can collide with other devices/products broadcasting the
// same placeholder. Replace with a registered Bluetooth SIG company ID,
// or at minimum a randomly-chosen value you've confirmed isn't in use
// on your campus, before any real-world multi-device deployment.
const uint16_t BLE_COMPANY_ID = 0xFFFF;

// ================= TIME SYNC SERVICE (fallback when NTP is unavailable) =================
// Separate GATT service, coexists with the advertising broadcast above.
// A phone writes its current unix time (as an ASCII decimal string,
// e.g. "1753000000") to this characteristic. Only accepted while the
// device has no valid time yet — see TimeSyncWriteCB below.
#define BLE_TIMESYNC_SERVICE_UUID "4e67a200-1234-5678-abcd-0123456789ab"
#define BLE_TIMESYNC_CHAR_UUID    "4e67a201-1234-5678-abcd-0123456789ab"

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

// ================= BLE GLOBALS =================
BLEAdvertising* bleAdvertising = nullptr;
bool bleReady = false;
uint32_t lastBroadcastedTokenWindow = 0; // avoids re-setting adv data every loop unnecessarily

BLEServer* bleServer = nullptr;                    // only used for the time-sync service
BLECharacteristic* timeSyncChar = nullptr;
volatile bool timeSyncPending = false;
String timeSyncPendingValue = "";

// ================= OBJECTS & GLOBALS =================
Adafruit_SH1106G display = Adafruit_SH1106G(128, 64, &Wire, -1);
MFRC522 rfid(RFID_CS, RFID_RST);
SPIClass sdSPI(HSPI); 
HardwareSerial fpSerial(2);
Adafruit_Fingerprint finger(&fpSerial);

// MODE_QR_BLE removed — BLE broadcast now runs concurrently within MODE_ATTENDANCE
enum DeviceMode { MODE_ATTENDANCE, MODE_ENROLLMENT, MODE_SYNC };
DeviceMode currentMode = MODE_ATTENDANCE;

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

bool sdAvailable = false;
volatile bool isTimeSynced = false;
volatile bool isWifiFailed = false;

// Real-time tracking for TOTP: captured once at NTP sync, then derived
// on demand via millis() offset — no physical RTC needed, matches the
// existing pattern already used for SD log timestamps.
time_t ntpSyncEpoch = 0;
unsigned long ntpSyncMillis = 0;

int enrollmentTargetIdx = -1; 

struct LogEvent {
  char logType; // 'A' for Attendance, 'E' for Enrollment
  char matric[25];
  char name[45];
  char method[15]; // "2FA" only now — BLE check-ins are logged server-side, not here
  char rfid[15];   
  int fp_id;       
  uint32_t scan_millis; 
};
QueueHandle_t sdQueue;
SemaphoreHandle_t displayMutex;
SemaphoreHandle_t sdMutex;

// ================= HELPER FUNCTIONS =================
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

    // Status badges, top right: [T]/[X]/[~] for time sync, [B] for BLE broadcasting
    display.setCursor(98, 0);
    if (isTimeSynced) display.print("[T]");
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

// ================= REAL-TIME HELPERS (no physical RTC) =================
// Returns best-effort current unix time, derived from the NTP sync
// captured at boot plus elapsed millis() since. If NTP never succeeded
// this returns 0 — TOTP broadcasting is skipped until time is known,
// since a wrong time produces wrong (and rejected) tokens.
time_t getCurrentUnixTime() {
  if (!isTimeSynced) return 0;
  return ntpSyncEpoch + ((millis() - ntpSyncMillis) / 1000);
}

// ================= TOTP GENERATION =================
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
  return binCode % 1000000; // 6 digits
}

void packTokenBCD(uint32_t sixDigitToken, uint8_t* out3Bytes) {
  char buf[7];
  snprintf(buf, sizeof(buf), "%06u", sixDigitToken);
  out3Bytes[0] = ((buf[0] - '0') << 4) | (buf[1] - '0');
  out3Bytes[1] = ((buf[2] - '0') << 4) | (buf[3] - '0');
  out3Bytes[2] = ((buf[4] - '0') << 4) | (buf[5] - '0');
}

uint32_t deviceShortCode() {
  // FNV-1a hash of DEVICE_ID, truncated to 4 bytes — stable per device,
  // doesn't need to be cryptographically strong, just a disambiguator.
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < DEVICE_ID.length(); i++) {
    hash ^= (uint8_t)DEVICE_ID[i];
    hash *= 16777619u;
  }
  return hash;
}

// ================= STUDENT DATA MANAGEMENT =================
int findStudentByRfid(const String& uid) { 
  for(int i=0; i<studentCount; i++) if(String(students[i].rfid) == uid) return i; 
  return -1; 
}

int findStudentByIdOrMatric(const String& searchId) { 
  for(int i=0; i<studentCount; i++) {
    if(String(students[i].id) == searchId || String(students[i].matric) == searchId) return i; 
  }
  return -1; 
}

int findNextUnenrolledStudent(int startIdx = 0) { 
  if (studentCount == 0) return -1;
  if (startIdx >= studentCount) startIdx = 0; 
  
  for(int i = startIdx; i < studentCount; i++) {
    if(strlen(students[i].rfid) == 0 || students[i].fingerprintId < 0) return i;
  }
  for(int i = 0; i < startIdx; i++) {
    if(strlen(students[i].rfid) == 0 || students[i].fingerprintId < 0) return i;
  }
  return -1; 
}

void loadStudentsFromSD() {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  if (!SD.exists("/TestingGroup8StudentDatabase.json")) { xSemaphoreGive(sdMutex); return; }
  
  File f = SD.open("/TestingGroup8StudentDatabase.json", FILE_READ);
  if (!f) { xSemaphoreGive(sdMutex); return; }
  
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, f);
  f.close();
  xSemaphoreGive(sdMutex);
  
  if (err || !doc.is<JsonArray>()) return;
  
  studentCount = 0;
  JsonArray arr = doc.as<JsonArray>();
  for (JsonVariant v : arr) {
    if (studentCount >= MAX_STUDENTS) break;
    StudentRecord rec;
    
    strlcpy(rec.id, v["id"] | "", sizeof(rec.id));
    strlcpy(rec.name, v["name"] | "", sizeof(rec.name));
    strlcpy(rec.matric, v["matric_number"] | "", sizeof(rec.matric));
    
    String tempRfid = String((const char*)(v["rfid_card_id"] | ""));
    tempRfid.trim(); tempRfid.toUpperCase();
    strlcpy(rec.rfid, tempRfid.c_str(), sizeof(rec.rfid));
    
    rec.fingerprintId = v["fingerprint_id"] | -1;
    
    if (strlen(rec.matric) > 0) students[studentCount++] = rec;
  }
}

void saveStudentsToSD() {
  if (!sdAvailable) return;
  xSemaphoreTake(sdMutex, portMAX_DELAY);
  SD.remove("/TestingGroup8StudentDatabase.json");
  File f = SD.open("/TestingGroup8StudentDatabase.json", FILE_WRITE);
  if (!f) { xSemaphoreGive(sdMutex); return; }
  
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < studentCount; i++) {
    JsonObject o = arr.createNestedObject();
    o["id"] = students[i].id;
    o["name"] = students[i].name;
    o["matric_number"] = students[i].matric;
    o["rfid_card_id"] = students[i].rfid;
    o["fingerprint_id"] = students[i].fingerprintId;
  }
  serializeJson(doc, f);
  f.close();
  xSemaphoreGive(sdMutex);
}

// ================= CLOUD SYNC LOGIC (hardware-sync, unchanged behavior) =================
bool uploadFileToCloud(const char* filePath, const char* displayLabel) {
  String url = String(CLOUD_BASE_URL) + String(SYNC_ENDPOINT);
  String fileType = String(filePath).indexOf("enrollment") >= 0 ? "enrollment" : "attendance";

  xSemaphoreTake(sdMutex, portMAX_DELAY);

  if (!SD.exists(filePath)) {
    xSemaphoreGive(sdMutex);
    return true; 
  }

  File file = SD.open(filePath, FILE_READ);
  if (!file) {
    xSemaphoreGive(sdMutex);
    return false;
  }

  size_t fileSize = file.size();
  if (fileSize == 0) {
    file.close();
    xSemaphoreGive(sdMutex);
    return true;
  }

  oledPrint("UPLOADING LOGS", String(displayLabel), "Reading SD...");
  Serial.println("[SYNC] Reading " + String(filePath) + " into memory...");

  String payload = file.readString();
  file.close();
  xSemaphoreGive(sdMutex); 

  oledPrint("UPLOADING LOGS", String(displayLabel), "Sending to Cloud...");
  
  WiFiClientSecure secureClient;
  secureClient.setInsecure();

  HTTPClient http;
  http.begin(secureClient, url);
  http.addHeader("Content-Type", "text/csv");
  http.addHeader("x-sync-file-type", fileType);
  http.addHeader("x-device-key", DEVICE_KEY);
  http.setTimeout(20000);

  Serial.println("[SYNC] Transmitting...");
  int httpCode = http.POST(payload);

  bool success = (httpCode >= 200 && httpCode < 300);
  if (success) {
    xSemaphoreTake(sdMutex, portMAX_DELAY);
    SD.remove(filePath);
    
    File f = SD.open(filePath, FILE_WRITE);
    if (f) { 
      if (String(filePath).indexOf("enrollment") >= 0) {
        f.println("Time,Name,Matric Number,RFID,Fingerprint ID"); 
      } else {
        f.println("Time,Name,Matric Number,Logging Type"); 
      }
      f.close(); 
    }
    
    xSemaphoreGive(sdMutex);
    Serial.println("[SYNC] " + String(displayLabel) + " uploaded & deleted. HTTP " + String(httpCode));
  } else {
    Serial.println("[SYNC] " + String(displayLabel) + " upload FAILED. HTTP " + String(httpCode));
  }

  http.end();
  delay(1000); 
  return success;
}

void syncDataToCloud() {
  oledPrint("CLOUD SYNC", "Starting Wi-Fi...");

  // BLE must fully deinit before WiFi comes up — ESP32 shares one 2.4GHz
  // radio, both stacks active at once is what used to crash the board.
  if (bleReady) {
    BLEDevice::deinit(true);
    bleReady = false;
    bleAdvertising = nullptr;
    bleServer = nullptr;
    timeSyncChar = nullptr;
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
    oledPrint("SYNC FAILED", "Check Wi-Fi router", "or credentials.");
    beepError();
    delay(3000);
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    currentMode = MODE_ATTENDANCE;
    initBLEBroadcast(); // resume broadcasting now that WiFi is off again
    oledPrint("SYSTEM READY", modeName());
    return;
  }

  oledPrint("CLOUD SYNC", "Wi-Fi Connected!", "SYNCING...");
  beepSuccess();

  bool attOk = uploadFileToCloud("/attendance.csv", "ATTENDANCE");
  bool enrOk = uploadFileToCloud("/enrollment.csv", "ENROLLMENT");

  if (attOk && enrOk) {
    oledPrint("SYNC COMPLETE", "Data uploaded safely.");
    beepSuccess();
  } else {
    String failMsg = "";
    if (!attOk) failMsg += "Attendance ";
    if (!enrOk) failMsg += "Enrollment ";
    oledPrint("SYNC FAILED", failMsg + "error", "Check Serial log.");
    beepError();
  }
  delay(2500);

  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);

  currentMode = MODE_ATTENDANCE;
  initBLEBroadcast(); // resume broadcasting after sync completes
  oledPrint("SYSTEM READY", modeName());
}

// ================= TIME SYNC CALLBACK =================
// Runs on the BLE stack's own task context — keep this minimal, just
// stash the value and let the main loop apply it, same pattern the
// old v1 GATT write handler used for safety.
class TimeSyncWriteCB : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pChar) override {
    if (isTimeSynced) return; // already have valid time — ignore, don't override
    String v = pChar->getValue();
    if (v.length() == 0 || v.length() > 12) return; // sanity bound
    timeSyncPendingValue = v;
    timeSyncPending = true;
  }
};

// Called from the main loop — validates and applies a pending phone
// time-sync write. Kept out of the BLE callback itself since callbacks
// run on a separate task and shouldn't do heavy work.
void applyPendingTimeSyncIfAny() {
  if (!timeSyncPending) return;
  timeSyncPending = false;

  if (isTimeSynced) return; // race guard — NTP may have won in the meantime

  // Basic plausibility bounds: reject anything before this firmware was
  // written (2026-01-01) or implausibly far in the future, so a stray
  // or malformed write can't set a wildly wrong clock.
  time_t candidate = (time_t) strtoul(timeSyncPendingValue.c_str(), nullptr, 10);
  const time_t MIN_PLAUSIBLE = 1767225600; // 2026-01-01T00:00:00Z
  const time_t MAX_PLAUSIBLE = 2082758400; // 2036-01-01T00:00:00Z
  if (candidate < MIN_PLAUSIBLE || candidate > MAX_PLAUSIBLE) {
    Serial.println("[TIMESYNC] Rejected implausible phone-supplied time.");
    return;
  }

  ntpSyncEpoch = candidate;
  ntpSyncMillis = millis();
  isTimeSynced = true;

  Serial.println("[TIMESYNC] Time set from phone (NTP was unavailable).");
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.fillRect(98, 0, 30, 8, SH110X_BLACK);
    display.setCursor(98, 0);
    display.setTextColor(SH110X_WHITE);
    display.print("[T]");
    display.display();
    xSemaphoreGive(displayMutex);
  }

  lastBroadcastedTokenWindow = 0; // force the broadcast to pick up the new time immediately
}

// ================= BLE BROADCAST (replaces old GATT server) =================
// Pure advertiser — the module never receives anything over BLE anymore.
// Phones passively scan, read the token, and submit check-ins directly
// to the server over their own internet connection.
void initBLEBroadcast() {
  if (bleReady) return; // already running

  BLEDevice::init(String("AttendESP_") + DEVICE_ID);
  BLEDevice::setPower(ESP_PWR_LVL_P9); // consider lowering this once real
                                        // classroom range testing is done —
                                        // physically limiting broadcast
                                        // range is your best proximity floor

  bleAdvertising = BLEDevice::getAdvertising();
  bleAdvertising->setScanResponse(false);
  bleAdvertising->setMinPreferred(0x06);

  // Time-sync GATT service — coexists with advertising above, no radio
  // conflict. Present at all times for simplicity, but writes are only
  // acted on while isTimeSynced is false (see TimeSyncWriteCB).
  bleServer = BLEDevice::createServer();
  BLEService* timeSyncService = bleServer->createService(BLE_TIMESYNC_SERVICE_UUID);
  timeSyncChar = timeSyncService->createCharacteristic(
    BLE_TIMESYNC_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE
  );
  timeSyncChar->setCallbacks(new TimeSyncWriteCB());
  timeSyncService->start();

  // Start advertising immediately, even before any valid token exists —
  // otherwise, if NTP never succeeds, the device is never discoverable
  // at all, and the time-sync fallback (which needs to find and connect
  // to it) can never run. updateBLEBroadcastToken() fills in the real
  // manufacturer data once time is known; until then this is a bare,
  // connectable advertisement carrying just the device name.
  bleAdvertising->start();

  bleReady = true;
  lastBroadcastedTokenWindow = 0; // force an immediate payload update
}

// Call frequently from loop() — cheap no-op unless the 30s window rolled over
void updateBLEBroadcastToken() {
  if (!bleReady || !isTimeSynced) return;

  time_t now = getCurrentUnixTime();
  if (now == 0) return;

  uint32_t currentWindow = now / TOTP_TIME_STEP;
  if (currentWindow == lastBroadcastedTokenWindow) return; // no change yet

  lastBroadcastedTokenWindow = currentWindow;

  uint32_t token = computeTOTP6Digit(now);
  uint8_t tokenBCD[3];
  packTokenBCD(token, tokenBCD);

  uint32_t shortCode = deviceShortCode();

  uint8_t mfgData[9];
  mfgData[0] = BLE_COMPANY_ID & 0xFF;
  mfgData[1] = (BLE_COMPANY_ID >> 8) & 0xFF;
  mfgData[2] = (shortCode >> 24) & 0xFF;
  mfgData[3] = (shortCode >> 16) & 0xFF;
  mfgData[4] = (shortCode >> 8) & 0xFF;
  mfgData[5] = shortCode & 0xFF;
  mfgData[6] = tokenBCD[0];
  mfgData[7] = tokenBCD[1];
  mfgData[8] = tokenBCD[2];

  String mfgStr((char*)mfgData, 9);

  BLEAdvertisementData advData;
  advData.setFlags(0x06); // BR/EDR not supported, general discoverable
  advData.setManufacturerData(mfgStr);

  bleAdvertising->stop();
  bleAdvertising->setAdvertisementData(advData);
  bleAdvertising->start();

  Serial.println("[BLE] Broadcasting token window " + String(currentWindow) + " (token hidden from serial log)");
}

// ================= FINGERPRINT ENROLLMENT LOGIC (unchanged) =================
int enrollFingerprint() {
  finger.getTemplateCount();
  int id = finger.templateCount + 1; 
  if (id > 127) return -1; 

  int p = -1;
  unsigned long timeoutTimer;

  oledPrint("PLACE FINGER", "ID: " + String(id));
  timeoutTimer = millis();
  while (p != FINGERPRINT_OK) { 
    p = finger.getImage(); 
    if (millis() - timeoutTimer > 10000) { beepError(); return -1; }
    delay(50); 
  }
  
  p = finger.image2Tz(1);
  if (p != FINGERPRINT_OK) { beepError(); return -1; }

  oledPrint("REMOVE FINGER");
  beepClick();
  delay(2000);
  
  p = 0;
  timeoutTimer = millis();
  while (p != FINGERPRINT_NOFINGER) { 
    p = finger.getImage(); 
    if (millis() - timeoutTimer > 10000) { beepError(); return -1; }
    delay(50); 
  }

  oledPrint("PLACE FINGER", "AGAIN");
  p = -1;
  timeoutTimer = millis();
  while (p != FINGERPRINT_OK) { 
    p = finger.getImage(); 
    if (millis() - timeoutTimer > 10000) { beepError(); return -1; }
    delay(50); 
  }

  p = finger.image2Tz(2);
  if (p != FINGERPRINT_OK) { beepError(); return -1; }

  p = finger.createModel();
  if (p == FINGERPRINT_OK) {
    p = finger.storeModel(id);
    if (p == FINGERPRINT_OK) return id;
  }
  
  beepError();
  return -1;
}

// ================= CORE 0: BACKGROUND TIME SYNC =================
void ntpSyncTask(void * pvParameters) {
  Serial.println("Background Task: Hunting for Wi-Fi time...");
  
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
    
    Serial.println("Background Task: Time Synced Successfully!");

    time(&ntpSyncEpoch);
    ntpSyncMillis = millis();
    isTimeSynced = true; 
    
    if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
      display.fillRect(98, 0, 30, 8, SH110X_BLACK);
      display.setCursor(98, 0);
      display.setTextColor(SH110X_WHITE);
      display.print("[T]");
      display.display();
      xSemaphoreGive(displayMutex);
    }

    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
  } else {
    Serial.println("Background Task: Wi-Fi Failed.");
    isWifiFailed = true; 
    
    if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
      display.fillRect(98, 0, 30, 8, SH110X_BLACK); 
      display.setCursor(98, 0);
      display.setTextColor(SH110X_WHITE);
      display.print("[X]");
      display.display();    
      xSemaphoreGive(displayMutex);
    }
    // NOTE: without WiFi/NTP, TOTP broadcasting stays disabled (see
    // getCurrentUnixTime) since a wrong clock produces tokens the
    // server will correctly reject anyway. RFID/FP attendance keeps
    // working fully offline regardless — only the BLE token path
    // depends on having gotten accurate time at least once at boot.
  }

  // BLE broadcasting can start now that WiFi is fully released,
  // regardless of whether time sync succeeded (it'll just wait quietly
  // for isTimeSynced if it didn't).
  initBLEBroadcast();

  vTaskDelete(NULL); 
}

// ================= CORE 0: SD CARD LOGGING TASK (unchanged) =================
void sdWriteTask(void * pvParameters) {
  LogEvent event;
  for(;;) {
    if (isTimeSynced || isWifiFailed) {
      if (xQueueReceive(sdQueue, &event, 10) == pdPASS) {
        if (sdAvailable) {
          char finalTimestamp[30];

          if (isTimeSynced) {
            time_t now; 
            time(&now); 
            time_t exact_scan_time = now - ((millis() - event.scan_millis) / 1000); 
            struct tm * timeinfo = localtime(&exact_scan_time);
            strftime(finalTimestamp, sizeof(finalTimestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
          } else {
            strcpy(finalTimestamp, "TIME_NOT_SYNCED");
          }

          xSemaphoreTake(sdMutex, portMAX_DELAY);
          
          if (event.logType == 'A') {
            File logFile = SD.open("/attendance.csv", FILE_APPEND);
            if (logFile) {
              logFile.print(finalTimestamp); logFile.print(",");
              logFile.print(event.name); logFile.print(",");
              logFile.print(event.matric); logFile.print(",");
              logFile.println(event.method);
              logFile.close();
            }
          } 
          else if (event.logType == 'E') {
            File logFile = SD.open("/enrollment.csv", FILE_APPEND);
            if (logFile) {
              logFile.print(finalTimestamp); logFile.print(",");
              logFile.print(event.name); logFile.print(",");
              logFile.print(event.matric); logFile.print(",");
              logFile.print(event.rfid); logFile.print(",");
              logFile.println(event.fp_id);
              logFile.close();
            }
          }
          
          xSemaphoreGive(sdMutex);
        }
      }
    } else {
      vTaskDelay(500 / portTICK_PERIOD_MS);
    }
  }
}

// ================= MASTER NAVIGATION =================
// Menu shrunk from 5 options to 4 — QR+BLE (old tap 3) is gone since
// BLE broadcasting now runs continuously in MODE_ATTENDANCE, it's no
// longer a separate mode to switch into.
void handleMasterNavigation() {
  beepClick();
  int menuTaps = 0;
  unsigned long lastTapTime = millis();
  const unsigned long MENU_TIMEOUT = 3000; 

  oledPrint("ADMIN MENU", "1:Attendance", "2:Enroll 3:Sync", "4:Wipe  Taps: 0");
  
  delay(1000); 

  while (millis() - lastTapTime < MENU_TIMEOUT) { 
    if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
      if (getRFIDString() == MASTER_RFID_UID) {
        menuTaps++;
        
        if (menuTaps > 4) {
          menuTaps = 1;
        }
        
        lastTapTime = millis(); 
        beepClick();
        oledPrint("ADMIN MENU", "1:Attendance", "2:Enroll 3:Sync", "4:Wipe  Taps: " + String(menuTaps));
        delay(500);
      }
    }
    delay(20);
  }

  // BLE stays running across Attendance <-> Enrollment (no memory
  // pressure reason to tear it down now that it's not a GATT server —
  // advertising alone is lightweight). Only Sync mode needs it off,
  // handled inside syncDataToCloud()/its resume path.

  if (menuTaps == 1 || menuTaps == 0) { 
    currentMode = MODE_ATTENDANCE;
    beepSuccess();
    oledPrint("MODE: ATTENDANCE", "Activated");
    delay(1200);
    oledPrint("SYSTEM READY", modeName());
  } 
  
  else if (menuTaps == 2) { 
    currentMode = MODE_ENROLLMENT;
    enrollmentTargetIdx = findNextUnenrolledStudent(0); 
    beepSuccess();
    oledPrint("MODE: ENROLLMENT", "Activated");
    delay(1200);
    if (enrollmentTargetIdx >= 0) {
      oledPrint("ENROLL:", String(students[enrollmentTargetIdx].name), "Card=Save | FP=Skip");
    } else {
      oledPrint("ENROLLMENT", "All onboarded!");
      delay(1500);
      currentMode = MODE_ATTENDANCE;
      oledPrint("SYSTEM READY", modeName());
    }
  } 
  
  else if (menuTaps == 3) {
    currentMode = MODE_SYNC;
    beepSuccess();
    oledPrint("MODE: CLOUD SYNC", "Activated");
    delay(1200);
  }
  
  else if (menuTaps >= 4) { 
    beepError(); 
    oledPrint("WIPE SYSTEM?", "Card = YES", "Finger = NO");
    
    unsigned long confirmTimeout = millis();
    bool wipeConfirmed = false;
    
    while (millis() - confirmTimeout < 10000) {
      if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
        rfid.PICC_HaltA(); 
        wipeConfirmed = true;
        break; 
      }
      if (finger.getImage() == FINGERPRINT_OK) {
        while(finger.getImage() != FINGERPRINT_NOFINGER) { delay(50); }
        break; 
      }
      delay(50);
    }
    
    if (wipeConfirmed) {
      beepError(); 
      oledPrint("SYSTEM WIPE", "Erasing FP Sensor...");
      finger.emptyDatabase(); 
      delay(1000);

      oledPrint("SYSTEM WIPE", "Clearing SD Links...");
      for (int i = 0; i < studentCount; i++) {
        strlcpy(students[i].rfid, "", sizeof(students[i].rfid));
        students[i].fingerprintId = -1;
      }
      saveStudentsToSD(); 

      beepSuccess();
      oledPrint("WIPE COMPLETE", "Restarting Board...");
      delay(2000);
      ESP.restart(); 
      
    } else {
      beepClick();
      oledPrint("WIPE CANCELLED", "Data is Safe");
      delay(1500);
      currentMode = MODE_ATTENDANCE;
      oledPrint("SYSTEM READY", modeName());
    }
  }
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  Serial.println("\n=== AttendESP v2 Booting ===");

  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);

  displayMutex = xSemaphoreCreateMutex();
  sdMutex = xSemaphoreCreateMutex();
  sdQueue = xQueueCreate(20, sizeof(LogEvent)); 

  Wire.begin(OLED_SDA, OLED_SCL);
  display.begin(OLED_ADDR, true);
  oledPrint("AttendESP v2", "Booting Hardware...");

  SPI.begin(RFID_SCK, RFID_MISO, RFID_MOSI);
  rfid.PCD_Init();

  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if (SD.begin(SD_CS, sdSPI)) {
    sdAvailable = true;
    if (!SD.exists("/attendance.csv")) {
      File f = SD.open("/attendance.csv", FILE_WRITE);
      if (f) { f.println("Time,Name,Matric Number,Logging Type"); f.close(); }
    }
    if (!SD.exists("/enrollment.csv")) {
      File f = SD.open("/enrollment.csv", FILE_WRITE);
      if (f) { f.println("Time,Name,Matric Number,RFID,Fingerprint ID"); f.close(); }
    }
  } else {
    oledPrint("SD WARNING", "Not Found!");
    delay(2000);
  }

  fpSerial.begin(57600, SERIAL_8N1, FP_RX, FP_TX);
  finger.begin(57600);

  while (fpSerial.available()) {
    fpSerial.read(); 
  }

  bool fpFound = false;
  for (int i = 0; i < 3; i++) {
    if (finger.verifyPassword()) {
      fpFound = true;
      break; 
    }
    delay(200); 
  }

  if (!fpFound) {
    oledPrint("FP WARNING", "Not Found!");
    delay(2000);
  }

  loadStudentsFromSD();

  xTaskCreatePinnedToCore(sdWriteTask, "SDTask", 8000, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(ntpSyncTask, "NTPTask", 4000, NULL, 1, NULL, 0);
  // initBLEBroadcast() is called at the end of ntpSyncTask, once WiFi
  // has fully released the radio — not called directly here.

  oledPrint("SYSTEM READY", modeName());
}

// ================= CORE 1: MAIN LOOP =================
void loop() {
  
  if (currentMode == MODE_SYNC) {
    syncDataToCloud(); 
    return;
  }

  // BLE token broadcast — runs every loop iteration, but is itself a
  // cheap no-op unless the 30s window has actually rolled over. Runs
  // concurrently with RFID/FP scanning below, no mode gating.
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
      
      while(finger.getImage() != FINGERPRINT_NOFINGER) { delay(50); }
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
            strcpy(enrollLog.matric, t.matric);
            strcpy(enrollLog.name, t.name);
            strcpy(enrollLog.rfid, t.rfid);
            enrollLog.fp_id = newFingerID;
            enrollLog.scan_millis = millis(); 
            xQueueSend(sdQueue, &enrollLog, 0);
            
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
    }
    
    else if (currentMode == MODE_ATTENDANCE) {
      beepClick();
      
      int stuIdx = findStudentByRfid(scannedUID);
      if (stuIdx >= 0) {
        oledPrint("CARD VERIFIED", String(students[stuIdx].name), "Place Finger...");
        
        unsigned long fpTimeout = millis();
        int matchedFingerID = -1;
        bool sensorTouched = false;
        
        while(millis() - fpTimeout < 5000) {
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
          strcpy(newLog.matric, students[stuIdx].matric);
          strcpy(newLog.name, students[stuIdx].name);
          strcpy(newLog.method, "2FA");
          newLog.scan_millis = millis(); 
          xQueueSend(sdQueue, &newLog, 0);
          
        } 
        else if (sensorTouched) {
          oledPrint("ACCESS DENIED", "ID MISMATCH", "Wrong fingerprint");
          beepError();
        } 
        else {
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
