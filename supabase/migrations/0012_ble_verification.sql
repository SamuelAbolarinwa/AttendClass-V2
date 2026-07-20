-- =============================================================================
-- 0012: BLE TOTP Verification Schema Updates
-- =============================================================================
SET search_path TO public, extensions;

-- ── 1. Update devices table ─────────────────────────────────────────────────
ALTER TABLE devices
  ADD COLUMN ble_short_code bigint;

COMMENT ON COLUMN devices.ble_short_code IS 'FNV-1a hash of the device_id used for compact BLE broadcasting.';

-- ── 2. Update attendance_logs table ─────────────────────────────────────────
ALTER TABLE attendance_logs
  ADD COLUMN totp_verified boolean DEFAULT false;

COMMENT ON COLUMN attendance_logs.totp_verified IS 'True if the check-in successfully cryptographically verified the device''s TOTP.';

-- ── 3. Secure the TOTP secret ───────────────────────────────────────────────
-- Prevent anon and authenticated users from reading the secret via API
REVOKE SELECT (totp_secret_encrypted) ON devices FROM anon, authenticated;

-- Add a comment clarifying the naming convention
COMMENT ON COLUMN devices.totp_secret_encrypted IS 'Base32 encoded TOTP secret. The "_encrypted" suffix is aspirational for future encryption-at-rest; currently it is stored as plain base32 but column-level SELECT is revoked from clients.';

-- ── 4. Seed / Update the demo ESP32 device ──────────────────────────────────
INSERT INTO devices (device_id, name, location, rssi_threshold_dbm, path_loss_exponent, ble_short_code, totp_secret_encrypted)
VALUES (
  'ESP32-LT101', 
  'Demo Lecture Hall ESP32', 
  'Room 101', 
  -80, 
  2.5, 
  3472223699, 
  'L7MBIGLP4BUXOHGZGZDSFRE2GL6HGRJF'
)
ON CONFLICT (device_id) DO UPDATE SET 
  ble_short_code = EXCLUDED.ble_short_code,
  totp_secret_encrypted = EXCLUDED.totp_secret_encrypted;
