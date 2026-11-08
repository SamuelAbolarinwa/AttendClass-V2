# AttendClass BLE Protocol v1 Specification (ATTENDCLASS_PROTOCOL_V1)

**Status**: Authoritative Standard  
**Version**: 1.0.0  
**Target Firmware**: AttendESP v3 (`firmware/AttendESP_v3/AttendESP_v3.ino`)  
**Target Mobile Execution Path**: `AttendClass-Mobile` (`src/services/AttendanceManager.ts` + `AttendanceProtocol.ts`)  
**Target Backend**: `AttendClass-V2` (`supabase/functions/hardware-sync`, migration `0017`)  

---

## 1. Overview & Single Source of Truth

This document resolves overlapping and divergent protocol drafts across repositories, establishing **ONE canonical wire protocol** for the AttendClass offline classroom attendance system.

### 1.1 Operating Architecture
```
┌──────────────────────────────────────────────┐
│             Student Mobile Phone             │
│   (Hardware-backed Keystore, NIST P-256)     │
└──────────────────────┬───────────────────────┘
                       │ BLE GATT (Service 0000ff10-...)
                       │ Binary MTU-23 Framing (0xAC, 0x01)
┌──────────────────────▼───────────────────────┐
│        AttendESP v3 Classroom Terminal       │
│  (ESP32, mbedtls P-256, MicroSD Persistence) │
└──────────────────────┬───────────────────────┘
                       │ HTTPS (Direct Wi-Fi via x-device-key) OR
                       │ BLE Bridge via Authorised Admin Phone
┌──────────────────────▼───────────────────────┐
│            Supabase Cloud Backend            │
│   (Edge Function: hardware-sync, DB v0017)   │
└──────────────────────────────────────────────┘
```

---

## 2. Bluetooth GATT Profile & Characteristic Definitions

All Bluetooth Low Energy communications MUST use the custom 128-bit GATT Service and Characteristic UUIDs implemented in `AttendESP_v3.ino`:

| Name | UUID | Properties | Description |
|---|---|---|---|
| **Primary Service** | `0000ff10-0000-1000-8000-00805f9b34fb` | Service | Root Offline Attendance Service |
| **Challenge Char** | `0000ff11-0000-1000-8000-00805f9b34fb` | READ, NOTIFY | ESP32 emits dynamic single-use challenge nonce |
| **Submission Char** | `0000ff12-0000-1000-8000-00805f9b34fb` | WRITE, WRITE_NO_RESP | Phone sends framed attendance submission or reconciliation query |
| **Receipt / ACK Char**| `0000ff13-0000-1000-8000-00805f9b34fb` | READ, NOTIFY | ESP32 emits signed receipt ONLY after durable SD write |
| **Provisional Time** | `0000ff01-0000-1000-8000-00805f9b34fb` | WRITE | Phone writes Unix epoch seconds to sync provisional clock |

> [!IMPORTANT]
> The experimental UUID `4e67a100-1234-5678-abcd-0123456789ab` and HELLO/PROOF flow in `src/ble/BleProtocol.ts` is superseded by this specification and MUST NOT be called against AttendESP v3 terminals.

---

## 3. Binary Framing Layer (MTU 23 Compatibility)

All payloads over characteristics `0000ff11`, `0000ff12`, and `0000ff13` are split into MTU-safe binary frames:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Magic (0xAC) | Version(0x01) |       Transaction ID (16-bit) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Sequence Num |  Total Chunks |         Payload Bytes...      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Magic Byte**: `0xAC` (172)
- **Version Byte**: `0x01` (1)
- **Transaction ID**: 16-bit big-endian integer matching the lower 16 bits of the event hash.
- **Sequence Number**: 1-indexed (`1 <= seq <= total_chunks`).
- **Total Chunks**: Total number of frames (`1 <= total_chunks <= 255`).
- **Chunk Size at MTU 23**: Maximum 14 payload bytes per frame (total frame length <= 20 bytes).

---

## 4. Canonical Cryptographic Representations & Interoperability

### 4.1 Key Formats
- **Algorithm**: `ECDSA_P256_SHA256` (`secp256r1` / `prime256v1` with SHA-256).
- **Public Key**: Uncompressed X.509 `SubjectPublicKeyInfo` (SPKI) DER Base64 (exactly 91 bytes raw, 124 characters Base64, header `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...`).
- **Signature Encodings**:
  - Compact IEEE P1363: 64 raw bytes `(R || S)` encoded in Base64 (88 characters).
  - ASN.1 DER: Sequence of two integers with low-S canonicality (`s <= order/2`).
  - Both encodings MUST be converted losslessly by the backend and mobile clients.

### 4.2 Terminal Challenge (0000ff11)
Emitted by ESP32 upon BLE connection:
```json
{
  "version": 1,
  "terminal_id": "TERM-LAB1-01",
  "session_id": "sess_20261006",
  "challenge": "4Z1u9QhYx8...",
  "terminal_time": 1791298800,
  "time_confidence": "rtc" | "unsynchronized" | "estimated",
  "course_code": "CSC401",
  "signature": "<Terminal_P256_Signature_Base64>"
}
```
**Canonical Message for Challenge Signing**:
```
v1|challenge|{terminal_id}|{session_id}|{challenge}|{terminal_time}|{time_confidence}|{course_code}
```
*Expiry*: Challenge nonces expire monotonically after 60,000 ms.

### 4.3 Student Attendance Submission (0000ff12)
Transmitted by Phone to ESP32:
```json
{
  "version": 1,
  "event_id": "c1f7b0a8-4e3d-4c8e-9d8a-6b2f4e8a1d2c",
  "credential_id": "cred-p256-01",
  "credential_version": "v1",
  "algorithm": "ECDSA_P256_SHA256",
  "student_id": "std-uuid-001",
  "matric_number": "2021/1/12345CP",
  "terminal_id": "TERM-LAB1-01",
  "session_id": "sess_20261006",
  "challenge": "4Z1u9QhYx8...",
  "timestamp": 1791298800,
  "timestamp_source": "phone_os",
  "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
  "signature": "<Student_P256_Signature_Base64>"
}
```
**Canonical Message for Submission Signing**:
```
v1|submission|{event_id}|{credential_id}|{credential_version}|{algorithm}|{student_id}|{matric_number}|{terminal_id}|{session_id}|{challenge}|{timestamp}|{timestamp_source}
```

### 4.4 Terminal Acknowledgement / Receipt (0000ff13)
Emitted by ESP32 ONLY after record is durably flushed to `/attendance_offline.csv`:
```json
{
  "version": 1,
  "event_id": "c1f7b0a8-4e3d-4c8e-9d8a-6b2f4e8a1d2c",
  "terminal_id": "TERM-LAB1-01",
  "session_id": "sess_20261006",
  "submission_digest": "<SHA-256_Hex_of_Canonical_Submission>",
  "status": "DURABLY_SAVED",
  "sd_persisted": true,
  "record_index": 142,
  "saved_at": "2026-10-08T09:30:00Z",
  "signature": "<Terminal_P256_Signature_Base64>",
  "error_code": null
}
```
**Canonical Message for Receipt Signing**:
```
v1|receipt|{event_id}|{terminal_id}|{session_id}|{submission_digest}|{status}|{sd_persisted}|{record_index}|{saved_at}
```

### 4.5 Disconnect Reconciliation Query (0000ff12)
If connection drops during transmission, phone queries:
```
v1|reconcile|{eventId}|{studentId}
```
ESP32 returns the cached signed receipt if present in `/event_index.csv`.

---

## 5. Cloud Synchronization Contracts

### 5.1 Mobile Admin BLE Sync Bridge Contract
The phone connects to ESP32 over BLE, downloads unsynced records, and posts to `hardware-sync`:
```json
POST /functions/v1/hardware-sync
Content-Type: application/json

{
  "action": "sync_attendance_batch",
  "admin_token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "terminal_id": "TERM-LAB1-01",
  "records": [
    {
      "event_id": "c1f7b0a8-4e3d-4c8e-9d8a-6b2f4e8a1d2c",
      "student_id": "std-uuid-001",
      "matric_number": "2021/1/12345CP",
      "terminal_id": "TERM-LAB1-01",
      "session_id": "sess_20261006",
      "timestamp": 1791298800,
      "submission_digest": "a1b2c3d4...",
      "terminal_receipt_signature": "MEUCIQD...",
      "terminal_saved_at": "2026-10-08T09:30:00Z",
      "public_key": "MFkwEw...",
      "signature": "MEQCIG..."
    }
  ]
}
```

### 5.2 Server Response Contract
```json
{
  "ok": true,
  "accepted": 1,
  "duplicate": 0,
  "rejected": 0,
  "retryable": 0,
  "rows_received": 1,
  "records": [
    {
      "event_id": "c1f7b0a8-4e3d-4c8e-9d8a-6b2f4e8a1d2c",
      "matric_number": "2021/1/12345CP",
      "status": "ACCEPTED"
    }
  ],
  "enrolled_keys": [
    {
      "student_id": "std-uuid-001",
      "matric_number": "2021/1/12345CP",
      "public_key": "MFkwEw...",
      "credential_id": "cred-p256-01",
      "algorithm": "ECDSA_P256_SHA256"
    }
  ]
}
```

---

## 6. ESP32 Provisioning Bundle Contract

The offline ESP32 stores active keys in `/enrolled_keys.csv`:
```csv
matric,student_id,public_key,credential_id,algorithm,revoked
2021/1/12345CP,std-uuid-001,MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...,cred-p256-01,ECDSA_P256_SHA256,false
```
Terminals reject any check-in from a key not listed in `/enrolled_keys.csv` with `STUDENT_NOT_ENROLLED` or `UNAUTHORIZED_PUBLIC_KEY`.
