# AttendClass v2

Classroom attendance system backed by Supabase.

## Project Structure

```
supabase/
├── config.toml                        # Supabase project config
├── migrations/
│   └── 0001_init_schema.sql           # Database schema (13 tables, 3 enums)
└── functions/
    └── hardware-sync/
        └── index.ts                   # ESP32 CSV upload endpoint
```

---

## Edge Functions

### `hardware-sync`

Drop-in replacement for the endpoint the ESP32 firmware calls to upload
attendance and enrollment CSV data.

| Detail          | Value                                                      |
| --------------- | ---------------------------------------------------------- |
| Method          | `POST`                                                     |
| Content-Type    | `text/csv`                                                 |
| Auth            | `x-device-key` header (SHA-256 matched against DB)         |
| JWT required?   | **No** — disabled in `config.toml`                         |

#### Headers

| Header              | Required | Values                           |
| ------------------- | -------- | -------------------------------- |
| `x-device-key`      | ✅        | Static secret flashed into ESP32 |
| `x-sync-file-type`  | ✅        | `attendance` or `enrollment`     |

#### CSV Formats

**Attendance** (`x-sync-file-type: attendance`):
```
Time,Name,Matric Number,Logging Type
2026-07-13 10:05:00,John Doe,ENG/2022/001,2FA
2026-07-13 10:06:12,Jane Smith,ENG/2022/042,QR_BLE
```

**Enrollment** (`x-sync-file-type: enrollment`):
```
Time,Name,Matric Number,RFID,Fingerprint ID
2026-07-13 09:00:00,John Doe,ENG/2022/001,AB:CD:EF:12,3
2026-07-13 09:01:00,Jane Smith,ENG/2022/042,12:34:56:78,7
```

The header row is optional — the function auto-detects and skips it.

#### Response

```json
{
  "rows_received": 2,
  "rows_processed": 2,
  "rows_failed": 0
}
```

The firmware only checks for HTTP 2xx vs non-2xx. Partial processing still
returns `200` so the firmware doesn't retry the entire file.

---

## Local Development

### Prerequisites

```bash
npm install -g supabase    # or use npx
supabase login
supabase link --project-ref <your-project-ref>
```

### Start local Supabase

```bash
supabase start
```

### Serve Edge Functions locally

```bash
supabase functions serve
```

This starts functions at `http://127.0.0.1:54321/functions/v1/`.

### Register a test device

Before testing `hardware-sync`, you need a device row with a matching key
hash. The function uses **SHA-256** hex digest of the `x-device-key` value.

Generate a hash for your test key (e.g. key = `test-device-secret-123`):

```bash
echo -n "test-device-secret-123" | sha256sum
# Output: <hash>  -
```

Insert a device via the Supabase Studio SQL editor or psql:

```sql
INSERT INTO devices (device_id, name, device_key_hash)
VALUES (
  'ESP32-TEST-01',
  'Test Device',
  '<paste-sha256-hex-here>'
);
```

### Test with curl

**Attendance upload:**

```bash
curl -X POST http://127.0.0.1:54321/functions/v1/hardware-sync \
  -H "Content-Type: text/csv" \
  -H "x-sync-file-type: attendance" \
  -H "x-device-key: test-device-secret-123" \
  --data-raw 'Time,Name,Matric Number,Logging Type
2026-07-13 10:05:00,John Doe,ENG/2022/001,2FA
2026-07-13 10:06:12,Jane Smith,ENG/2022/042,QR_BLE'
```

**Enrollment upload:**

```bash
curl -X POST http://127.0.0.1:54321/functions/v1/hardware-sync \
  -H "Content-Type: text/csv" \
  -H "x-sync-file-type: enrollment" \
  -H "x-device-key: test-device-secret-123" \
  --data-raw 'Time,Name,Matric Number,RFID,Fingerprint ID
2026-07-13 09:00:00,John Doe,ENG/2022/001,AB:CD:EF:12,3'
```

**Expected:** `200 OK` with a JSON summary. If no matching student profiles
exist yet, `rows_failed` will be non-zero but the raw rows will still be
saved in `hardware_sync_log` for later reprocessing.

---

## Deploying & Pointing the ESP32

### Deploy the function

```bash
supabase functions deploy hardware-sync --no-verify-jwt
```

### Get your project URL

Your function will be live at:

```
https://<project-ref>.supabase.co/functions/v1/hardware-sync
```

### Update ESP32 firmware

In your ESP32 firmware's `config.h` (or equivalent), set:

```cpp
#define CLOUD_BASE_URL "https://<project-ref>.supabase.co/functions/v1"
```

The firmware already POSTs to `CLOUD_BASE_URL + "/hardware-sync"`, so no
other firmware changes are needed.

### Set the device key

Each ESP32 has a `DEVICE_KEY` in its firmware config. When you register the
device in the `devices` table, store the **SHA-256 hex digest** of that key
in the `device_key_hash` column.

---

## Device Key Hashing Convention

This project uses **SHA-256** (not bcrypt) for `devices.device_key_hash`.

**Rationale:** SHA-256 allows a direct `WHERE device_key_hash = $1` query,
which is faster and simpler than loading all device rows for bcrypt
comparison. Since device keys are long random strings (not user-chosen
passwords), SHA-256 provides adequate security.

To generate a hash:

```bash
echo -n "your-device-key-here" | sha256sum | awk '{print $1}'
```

Or in JavaScript/Node:

```js
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('your-device-key-here').digest('hex');
```
