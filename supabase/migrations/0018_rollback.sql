-- =============================================================================
-- Rollback for 0018_time_provenance_and_verification.sql
-- =============================================================================
SET search_path TO public, extensions;

-- 1. Drop functions
DROP FUNCTION IF EXISTS admin_get_pending_attendance_reviews(uuid, text, integer);
DROP FUNCTION IF EXISTS admin_review_attendance_record(uuid, uuid, text, text);

-- 2. Drop indexes
DROP INDEX IF EXISTS idx_attendance_logs_terminal_time;
DROP INDEX IF EXISTS idx_attendance_logs_time_review;

-- 3. Drop constraints
ALTER TABLE attendance_logs DROP CONSTRAINT IF EXISTS chk_attendance_time_verification_status;
ALTER TABLE attendance_logs DROP CONSTRAINT IF EXISTS chk_attendance_time_source;

-- 4. Drop columns added in 0018
ALTER TABLE attendance_logs
  DROP COLUMN IF EXISTS review_notes,
  DROP COLUMN IF EXISTS reviewed_at,
  DROP COLUMN IF EXISTS reviewed_by,
  DROP COLUMN IF EXISTS server_received_at,
  DROP COLUMN IF EXISTS provenance_canonical,
  DROP COLUMN IF EXISTS terminal_provenance_sig,
  DROP COLUMN IF EXISTS time_verification_status,
  DROP COLUMN IF EXISTS time_source;

