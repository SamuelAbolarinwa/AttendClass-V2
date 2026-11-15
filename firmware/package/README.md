# AttendESP v3 Production Firmware Package

**Target Hardware**: Espressif ESP32-WROOM-32 (DevKit v1)  
**IDE/Toolchain**: Arduino IDE 2.x or PlatformIO  
**Board Package**: `esp32` by Espressif Systems (v2.0.14 or v3.0.x)  
**Partition Scheme**: `Huge APP (3MB No OTA/1MB SPIFFS)`  
**Protocol Standard**: [ATTENDCLASS_PROTOCOL_V1](../../docs/ATTENDCLASS_PROTOCOL_V1.md)  

---

## 1. Hardware Pin Connections

| Module | Pin Name | ESP32 GPIO | Description |
|---|---|---|---|
| **OLED SSD1306 (128x64)** | SDA | GPIO 21 | I2C Data |
| | SCL | GPIO 22 | I2C Clock |
| | VCC / GND | 3V3 / GND | Power |
| **RFID RC522 (SPI)** | SDA (SS) | GPIO 5 | Chip Select (VSPI) |
| | SCK | GPIO 18 | SPI Clock (VSPI) |
| | MOSI | GPIO 23 | SPI MOSI (VSPI) |
| | MISO | GPIO 19 | SPI MISO (VSPI) |
| | RST | GPIO 4 | Hardware Reset |
| **MicroSD Card (HSPI)** | CS | GPIO 27 | Chip Select (HSPI) |
| | MOSI | GPIO 13 | SPI MOSI (HSPI) |
| | MISO | GPIO 35 | SPI MISO (HSPI, input only) |
| | SCK | GPIO 14 | SPI Clock (HSPI) |
| **Optical Fingerprint** | RX | GPIO 32 | Sensor Green wire (ESP TX) |
| | TX | GPIO 33 | Sensor White wire (ESP RX) |
| | VCC / GND | 5V / GND | Power (5V required for sensor LED) |
| **Indicators** | Green LED | GPIO 2 | Success indicator |
| | Red LED | GPIO 26 | Error indicator |
| | Active Buzzer | GPIO 16 | Audio feedback |

---

## 2. MicroSD Card File Structure

Format the MicroSD card as **FAT32** with 32KB allocation unit size. Place the following files in the root:

```
/
├── terminal_key.bin            (REQUIRED: exactly 32 raw bytes of private scalar d)
├── enrolled_keys.csv           (REQUIRED: authorized student public key registry)
├── students.csv                (OPTIONAL: baseline 2FA biometric/RFID card database)
├── sync_checkpoint.txt         (SYSTEM: persistent cloud upload cursor)
├── attendance_offline.csv      (SYSTEM: append-only offline BLE check-in records)
├── event_index.csv             (SYSTEM: idempotency index & receipt cache)
└── rejected_records.csv        (SYSTEM: records rejected by cloud backend)
```

### 2.1 Generating `terminal_key.bin`
Generate a cryptographically secure 32-byte NIST P-256 scalar using OpenSSL:
```bash
openssl ecparam -name prime256v1 -genkey -noout -out terminal_priv.pem
openssl ec -in terminal_priv.pem -outform DER | tail -c 32 > terminal_key.bin
```

---

## 3. Required Arduino Libraries

Install the following exact library versions via the Arduino Library Manager:
- `Adafruit GFX Library` (v1.11.9)
- `Adafruit SSD1306` (v2.5.9)
- `MFRC522` (v1.4.11) by GithubCommunity
- `Adafruit Fingerprint Sensor Library` (v2.1.3)
- `ArduinoJson` (v7.0.4) by Benoit Blanchon
- `ESP32 BLE Arduino` (Built into ESP32 Arduino Core)

---

## 4. Flashing Procedure (Without Overwriting Baseline)

1. Open `AttendESP_v3.ino` in Arduino IDE.
2. Select Board: **ESP32 Dev Module**.
3. Select Partition Scheme: **Huge APP (3MB No OTA/1MB SPIFFS)**.
4. Set Upload Speed: **921600** (or **115200** if unstable).
5. Compile sketch to verify (Sketch -> Verify/Compile).
6. Flash to device only when physical terminal upgrade is scheduled.

