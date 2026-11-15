-- =============================================================================
-- 0017_rollback: Revert migration 0017
-- Safe and clean rollback script
-- =============================================================================
SET search_path TO public, extensions;

-- Drop RPC functions created in 0017
DROP FUNCTION IF EXISTS platform_get_device_audit_log(uuid, uuid, integer);
DROP FUNCTION IF EXISTS platform_get_enrolled_keys_csv(uuid);
DROP FUNCTION IF EXISTS admin_reject_device_change(uuid, uuid, text);
DROP FUNCTION IF EXISTS admin_approve_device_change(uuid, uuid, text);
DROP FUNCTION IF EXISTS platform_request_device_change(uuid, text);
DROP FUNCTION IF EXISTS admin_revoke_device(uuid, uuid, text);
DROP FUNCTION IF EXISTS platform_get_device_status(uuid);
DROP FUNCTION IF EXISTS platform_enroll_device(uuid, text, text, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS platform_request_enrollment_challenge(uuid);
DROP FUNCTION IF EXISTS admin_expire_activation_code(uuid, uuid);
DROP FUNCTION IF EXISTS admin_generate_device_activation_code(uuid, uuid, integer, text);
DROP FUNCTION IF EXISTS generate_activation_code();

-- Drop added indexes
DROP INDEX IF EXISTS idx_student_devices_one_active_per_student;
DROP INDEX IF EXISTS idx_device_audit_event;
DROP INDEX IF EXISTS idx_device_audit_student;
DROP INDEX IF EXISTS idx_device_change_requests_student;
DROP INDEX IF EXISTS idx_device_challenges_student;
DROP INDEX IF EXISTS idx_activation_attempt_student;
DROP INDEX IF EXISTS idx_device_activation_hash;
DROP INDEX IF EXISTS idx_device_activation_student;

-- Drop tables created in 0017
DROP TABLE IF EXISTS device_audit_log CASCADE;
DROP TABLE IF EXISTS device_change_requests CASCADE;
DROP TABLE IF EXISTS device_enrollment_challenges CASCADE;
DROP TABLE IF EXISTS device_activation_attempt_log CASCADE;
DROP TABLE IF EXISTS device_activation_codes CASCADE;

-- Drop columns added to student_devices, devices, attendance_logs
ALTER TABLE student_devices DROP COLUMN IF EXISTS credential_version;
ALTER TABLE student_devices DROP COLUMN IF EXISTS credential_id;
ALTER TABLE student_devices DROP COLUMN IF EXISTS algorithm;
ALTER TABLE student_devices DROP COLUMN IF EXISTS revocation_reason;
ALTER TABLE student_devices DROP COLUMN IF EXISTS last_seen_at;
ALTER TABLE student_devices DROP COLUMN IF EXISTS device_fingerprint;
ALTER TABLE student_devices DROP COLUMN IF EXISTS device_name;

ALTER TABLE devices DROP COLUMN IF EXISTS provisioned_version;
ALTER TABLE devices DROP COLUMN IF EXISTS last_sync_at;
ALTER TABLE devices DROP COLUMN IF EXISTS is_active;
ALTER TABLE devices DROP COLUMN IF EXISTS algorithm;
ALTER TABLE devices DROP COLUMN IF EXISTS public_key;

ALTER TABLE attendance_logs DROP COLUMN IF EXISTS offline_verified;
ALTER TABLE attendance_logs DROP COLUMN IF EXISTS submission_digest;
ALTER TABLE attendance_logs DROP COLUMN IF EXISTS terminal_receipt_sig;
ALTER TABLE attendance_logs DROP COLUMN IF EXISTS timestamp_source;
ALTER TABLE attendance_logs DROP COLUMN IF EXISTS phone_attendance_time;
ALTER TABLE attendance_logs DROP COLUMN IF EXISTS terminal_saved_at;
ALTER TABLE attendance_logs DROP COLUMN IF EXISTS terminal_id;
ALTER TABLE attendance_logs DROP COLUMN IF EXISTS event_id;
