-- =============================================================================
-- AttendClass v2 — Initial Schema Migration
-- Generated: 2026-07-12
-- =============================================================================

-- ---------------------------------------------------------------------------
-- ENUM TYPES
-- ---------------------------------------------------------------------------

CREATE TYPE user_role AS ENUM ('student', 'lecturer', 'course_rep');
COMMENT ON TYPE user_role IS 'Role a user holds in the system.';

CREATE TYPE attendance_method AS ENUM (
  '2fa_rfid_fp',        -- legacy 2FA: RFID card + fingerprint
  'qr_ble_legacy',      -- legacy QR scan with BLE proximity
  'face_ble_signed',    -- face recognition + BLE + device signature
  'fallback_pin'        -- lecturer-issued one-time PIN
);
COMMENT ON TYPE attendance_method IS 'How the student proved presence during check-in.';

CREATE TYPE sync_file_type AS ENUM ('attendance', 'enrollment');
COMMENT ON TYPE sync_file_type IS 'Type of CSV file uploaded from legacy ESP32 hardware.';


-- ---------------------------------------------------------------------------
-- 1. profiles
-- ---------------------------------------------------------------------------

CREATE TABLE profiles (
  id          uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  role        user_role   NOT NULL,
  full_name   text        NOT NULL,
  matric_number text      UNIQUE,  -- nullable; only students have a matric number
  created_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  profiles              IS 'Extended user profile linked 1-to-1 with auth.users.';
COMMENT ON COLUMN profiles.matric_number IS 'University matriculation number. NULL for lecturers.';

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY profiles_permissive ON profiles FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 2. student_credentials
-- ---------------------------------------------------------------------------

CREATE TABLE student_credentials (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id      uuid        NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
  rfid_card_id    text        UNIQUE,   -- nullable; legacy RFID card UID
  fingerprint_id  int,                  -- nullable; legacy fingerprint sensor template ID
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  student_credentials                IS 'Legacy hardware credentials (RFID + fingerprint) for a student.';
COMMENT ON COLUMN student_credentials.rfid_card_id   IS 'UID read from the MFRC522 RFID reader.';
COMMENT ON COLUMN student_credentials.fingerprint_id IS 'Template ID stored on the R307 fingerprint sensor.';

ALTER TABLE student_credentials ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY student_credentials_permissive ON student_credentials FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 3. courses
-- ---------------------------------------------------------------------------

CREATE TABLE courses (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  code       text        NOT NULL UNIQUE,
  title      text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  courses      IS 'University courses that track attendance.';
COMMENT ON COLUMN courses.code IS 'Short code, e.g. "ENG302".';

ALTER TABLE courses ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY courses_permissive ON courses FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 4. course_lecturers
-- ---------------------------------------------------------------------------

CREATE TABLE course_lecturers (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id   uuid NOT NULL REFERENCES courses   (id) ON DELETE CASCADE,
  lecturer_id uuid NOT NULL REFERENCES profiles   (id) ON DELETE CASCADE,
  UNIQUE (course_id, lecturer_id)
);

COMMENT ON TABLE course_lecturers IS 'Many-to-many: which lecturers teach which courses.';

ALTER TABLE course_lecturers ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY course_lecturers_permissive ON course_lecturers FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 5. enrollments
-- ---------------------------------------------------------------------------

CREATE TABLE enrollments (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
  course_id  uuid NOT NULL REFERENCES courses  (id) ON DELETE RESTRICT,
  UNIQUE (student_id, course_id)
);

COMMENT ON TABLE enrollments IS 'Students enrolled in courses for attendance tracking.';

ALTER TABLE enrollments ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY enrollments_permissive ON enrollments FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 6. devices
-- ---------------------------------------------------------------------------

CREATE TABLE devices (
  id                        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id                 text        NOT NULL UNIQUE,
  name                      text        NOT NULL,
  location                  text,
  totp_secret_encrypted     text,
  rssi_threshold_dbm        int         NOT NULL DEFAULT -80,
  rssi_at_1m_calibration    int,
  path_loss_exponent        numeric     NOT NULL DEFAULT 2.5,
  device_key_hash           text,
  created_at                timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  devices                           IS 'Registered ESP32 hardware units deployed in lecture halls.';
COMMENT ON COLUMN devices.device_id                 IS 'Unique hardware identifier flashed into firmware, e.g. "ESP32-LT101".';
COMMENT ON COLUMN devices.totp_secret_encrypted     IS 'AES-encrypted TOTP shared secret; populated when TOTP firmware ships.';
COMMENT ON COLUMN devices.rssi_threshold_dbm        IS 'BLE RSSI cutoff (dBm). Students farther than this are rejected.';
COMMENT ON COLUMN devices.rssi_at_1m_calibration    IS 'Measured RSSI at 1 m for distance estimation calibration.';
COMMENT ON COLUMN devices.path_loss_exponent        IS 'Environment path-loss exponent for log-distance model (typ. 2–4).';
COMMENT ON COLUMN devices.device_key_hash           IS 'Bcrypt/argon2 hash of the X-Device-Key header for legacy sync auth.';

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY devices_permissive ON devices FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 7. schedules
-- ---------------------------------------------------------------------------

CREATE TABLE schedules (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id   uuid NOT NULL REFERENCES courses (id) ON DELETE RESTRICT,
  device_id   uuid          REFERENCES devices (id) ON DELETE SET NULL,
  day_of_week int  NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
  start_time  time NOT NULL,
  end_time    time NOT NULL,
  CHECK (end_time > start_time)
);

COMMENT ON TABLE  schedules             IS 'Weekly recurring timetable slots for a course.';
COMMENT ON COLUMN schedules.day_of_week IS '0 = Sunday … 6 = Saturday (JS convention).';
COMMENT ON COLUMN schedules.device_id   IS 'ESP32 device assigned to the room; nullable if not yet assigned.';

ALTER TABLE schedules ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY schedules_permissive ON schedules FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 8. attendance_sessions
-- ---------------------------------------------------------------------------

CREATE TABLE attendance_sessions (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  schedule_id uuid        NOT NULL REFERENCES schedules (id) ON DELETE RESTRICT,
  device_id   uuid        NOT NULL REFERENCES devices   (id) ON DELETE RESTRICT,
  opened_at   timestamptz NOT NULL DEFAULT now(),
  closed_at   timestamptz,
  opened_by   uuid        REFERENCES profiles (id) ON DELETE SET NULL
);

COMMENT ON TABLE  attendance_sessions           IS 'A single check-in window opened for a scheduled class.';
COMMENT ON COLUMN attendance_sessions.opened_by IS 'Lecturer or course rep who started the session; NULL if auto-opened.';
COMMENT ON COLUMN attendance_sessions.closed_at IS 'NULL while session is still accepting check-ins.';

ALTER TABLE attendance_sessions ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY attendance_sessions_permissive ON attendance_sessions FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 9. attendance_logs
-- ---------------------------------------------------------------------------

CREATE TABLE attendance_logs (
  id                    uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id            uuid              REFERENCES attendance_sessions (id) ON DELETE CASCADE,
  student_id            uuid              NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
  method                attendance_method NOT NULL,
  verified_at           timestamptz       NOT NULL DEFAULT now(),
  rssi_dbm              int,
  estimated_distance_m  numeric,
  totp_token_used       text,
  signature_valid       boolean,
  face_similarity_score numeric,
  liveness_passed       boolean,
  raw_payload           jsonb,
  created_at            timestamptz       NOT NULL DEFAULT now()
);

COMMENT ON TABLE  attendance_logs                        IS 'Individual student check-in records.';
COMMENT ON COLUMN attendance_logs.session_id             IS 'NULL for rows imported from legacy CSV files that lack session context.';
COMMENT ON COLUMN attendance_logs.rssi_dbm               IS 'BLE RSSI reading at check-in time.';
COMMENT ON COLUMN attendance_logs.estimated_distance_m   IS 'Distance in metres derived from RSSI + calibration data.';
COMMENT ON COLUMN attendance_logs.totp_token_used        IS 'TOTP token submitted (for replay detection).';
COMMENT ON COLUMN attendance_logs.signature_valid         IS 'Whether the device-signed payload passed ECDSA/Ed25519 verification.';
COMMENT ON COLUMN attendance_logs.face_similarity_score  IS 'Cosine similarity between submitted and enrolled face embeddings.';
COMMENT ON COLUMN attendance_logs.liveness_passed        IS 'Result of passive/active liveness check during face verification.';
COMMENT ON COLUMN attendance_logs.raw_payload            IS 'Full JSON payload submitted by the client, kept for audit/debug.';

ALTER TABLE attendance_logs ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY attendance_logs_permissive ON attendance_logs FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 10. student_devices
-- ---------------------------------------------------------------------------

CREATE TABLE student_devices (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id        uuid        NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
  device_public_key text        NOT NULL,
  platform          text        NOT NULL,
  enrolled_at       timestamptz NOT NULL DEFAULT now(),
  revoked_at        timestamptz
);

COMMENT ON TABLE  student_devices                   IS 'Mobile devices registered by students for signed BLE check-in.';
COMMENT ON COLUMN student_devices.device_public_key IS 'Base64-encoded ECDSA or Ed25519 public key.';
COMMENT ON COLUMN student_devices.platform          IS 'Client platform, e.g. "ios", "android".';
COMMENT ON COLUMN student_devices.revoked_at        IS 'Non-NULL means this device is no longer trusted.';

ALTER TABLE student_devices ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY student_devices_permissive ON student_devices FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 11. face_enrollments
-- ---------------------------------------------------------------------------

CREATE TABLE face_enrollments (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id    uuid        NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
  embedding     float8[]    NOT NULL,
  model_version text        NOT NULL,
  active        boolean     NOT NULL DEFAULT true,
  enrolled_at   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  face_enrollments               IS 'Stored face embedding vectors for facial-recognition check-in.';
COMMENT ON COLUMN face_enrollments.embedding      IS 'Float64 vector produced by the embedding model (e.g. 128-d or 512-d).';
COMMENT ON COLUMN face_enrollments.model_version  IS 'Identifier of the model that produced this embedding, for compatibility.';
COMMENT ON COLUMN face_enrollments.active         IS 'False = soft-deleted / superseded by a newer enrollment.';

ALTER TABLE face_enrollments ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY face_enrollments_permissive ON face_enrollments FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 12. fallback_audit_log
-- ---------------------------------------------------------------------------

CREATE TABLE fallback_audit_log (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id     uuid        NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
  session_id     uuid        REFERENCES attendance_sessions (id) ON DELETE SET NULL,
  issued_by      uuid        NOT NULL REFERENCES profiles (id) ON DELETE RESTRICT,
  reason         text,
  pin_code_hash  text        NOT NULL,
  used_at        timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  fallback_audit_log               IS 'Audit trail for lecturer-issued fallback PINs.';
COMMENT ON COLUMN fallback_audit_log.issued_by     IS 'Lecturer (or course rep) who approved the fallback PIN.';
COMMENT ON COLUMN fallback_audit_log.pin_code_hash IS 'Bcrypt/argon2 hash of the one-time PIN.';
COMMENT ON COLUMN fallback_audit_log.used_at       IS 'NULL if the PIN was issued but never redeemed.';

ALTER TABLE fallback_audit_log ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY fallback_audit_log_permissive ON fallback_audit_log FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- 13. hardware_sync_log
-- ---------------------------------------------------------------------------

CREATE TABLE hardware_sync_log (
  id         uuid           PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id  uuid           NOT NULL REFERENCES devices (id) ON DELETE RESTRICT,
  file_type  sync_file_type NOT NULL,
  raw_row    jsonb          NOT NULL,
  processed  boolean        NOT NULL DEFAULT false,
  synced_at  timestamptz    NOT NULL DEFAULT now()
);

COMMENT ON TABLE  hardware_sync_log          IS 'Raw CSV rows ingested from legacy ESP32 hardware sync uploads.';
COMMENT ON COLUMN hardware_sync_log.raw_row  IS 'Single CSV row stored as JSON for idempotent reprocessing.';
COMMENT ON COLUMN hardware_sync_log.processed IS 'True once the row has been normalised into attendance_logs or enrollments.';

ALTER TABLE hardware_sync_log ENABLE ROW LEVEL SECURITY;
-- TODO: Add proper RLS policies (task TBD). Permissive placeholder below.
CREATE POLICY hardware_sync_log_permissive ON hardware_sync_log FOR ALL USING (true) WITH CHECK (true);


-- ---------------------------------------------------------------------------
-- INDEXES
-- ---------------------------------------------------------------------------

CREATE INDEX idx_attendance_logs_student_id  ON attendance_logs (student_id);
CREATE INDEX idx_attendance_logs_session_id  ON attendance_logs (session_id);
CREATE INDEX idx_enrollments_student_course  ON enrollments (student_id, course_id);
CREATE INDEX idx_student_credentials_rfid    ON student_credentials (rfid_card_id)
  WHERE rfid_card_id IS NOT NULL;


-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
