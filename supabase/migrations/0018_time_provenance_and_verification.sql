-- =============================================================================
-- 0018: Authenticated Time-Provenance, Clock Trust & Review Workflow
-- Handles provisional phone time safely, preserving legacy records and RLS
-- =============================================================================
SET search_path TO public, extensions;

-- ── 1. Add time provenance and review columns to attendance_logs ────────────
ALTER TABLE attendance_logs
  ADD COLUMN IF NOT EXISTS time_source text NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS time_verification_status text NOT NULL DEFAULT 'pending_review',
  ADD COLUMN IF NOT EXISTS terminal_provenance_sig text,
  ADD COLUMN IF NOT EXISTS provenance_canonical text,
  ADD COLUMN IF NOT EXISTS server_received_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS reviewed_by uuid REFERENCES profiles(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS reviewed_at timestamptz,
  ADD COLUMN IF NOT EXISTS review_notes text;

-- Add check constraints if they do not exist
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_attendance_time_source'
  ) THEN
    ALTER TABLE attendance_logs
      ADD CONSTRAINT chk_attendance_time_source
      CHECK (time_source IN ('ntp', 'rtc', 'provisional_phone', 'unsynchronized', 'unknown'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_attendance_time_verification_status'
  ) THEN
    ALTER TABLE attendance_logs
      ADD CONSTRAINT chk_attendance_time_verification_status
      CHECK (time_verification_status IN ('verified', 'pending_review', 'flagged_anomalous', 'rejected'));
  END IF;
END $$;

COMMENT ON COLUMN attendance_logs.time_source IS 'Origin of terminal recorded time: ntp (authenticated NTP), rtc (battery-backed RTC), provisional_phone (phone clock provisional fallback), unsynchronized, or unknown (legacy 16-field).';
COMMENT ON COLUMN attendance_logs.time_verification_status IS 'Verification status: verified (NTP attested or admin approved), pending_review (provisional or unverified), flagged_anomalous (skew or out-of-window), rejected.';
COMMENT ON COLUMN attendance_logs.terminal_provenance_sig IS 'Terminal ECDSA P-256 signature over the v2 canonical time-provenance statement.';
COMMENT ON COLUMN attendance_logs.provenance_canonical IS 'The canonical string signed by the terminal for time-provenance.';
COMMENT ON COLUMN attendance_logs.server_received_at IS 'Authoritative cloud ingest timestamp; strictly distinct from terminal_saved_at and phone_attendance_time.';

-- ── 2. Backfill existing records safely ─────────────────────────────────────
-- Non-offline records (direct web checkin / 2FA RFID+FP) had server-verified time
UPDATE attendance_logs
SET time_source = 'ntp',
    time_verification_status = 'verified'
WHERE (method IS NULL OR method::text != 'ble_offline_signed')
  AND time_source = 'unknown';

-- Existing offline signed records without a terminal provenance signature:
-- Mark as time_source = 'unknown' and time_verification_status = 'pending_review'
UPDATE attendance_logs
SET time_source = 'unknown',
    time_verification_status = 'pending_review'
WHERE method::text = 'ble_offline_signed'
  AND terminal_provenance_sig IS NULL
  AND time_source = 'unknown';

-- Flag any existing records with excessive clock skew (> 15 minutes between phone time and terminal time)
UPDATE attendance_logs
SET time_verification_status = 'flagged_anomalous'
WHERE method::text = 'ble_offline_signed'
  AND terminal_saved_at IS NOT NULL
  AND phone_attendance_time IS NOT NULL
  AND abs(extract(epoch from (terminal_saved_at - phone_attendance_time))) > 900
  AND time_verification_status = 'pending_review';

-- ── 3. Performance Indexes ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_attendance_logs_time_review
  ON attendance_logs (time_verification_status, time_source);

CREATE INDEX IF NOT EXISTS idx_attendance_logs_terminal_time
  ON attendance_logs (terminal_id, terminal_saved_at DESC);

-- ── 4. Admin RPC: Review & Reconcile Provisional Attendance Records ─────────
CREATE OR REPLACE FUNCTION admin_review_attendance_record(
  p_token uuid,
  p_event_id uuid,
  p_decision text, -- 'verified' | 'rejected' | 'flagged_anomalous'
  p_notes text DEFAULT NULL
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _log attendance_logs%ROWTYPE;
BEGIN
  -- Verify admin/manager session
  SELECT * INTO _sess FROM active_sessions WHERE token = p_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized: invalid or expired session');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied: administrator or manager role required');
  END IF;

  IF p_decision NOT IN ('verified', 'rejected', 'flagged_anomalous') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid decision: expected "verified", "rejected", or "flagged_anomalous"');
  END IF;

  SELECT * INTO _log FROM attendance_logs WHERE event_id = p_event_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Attendance record not found');
  END IF;

  UPDATE attendance_logs
  SET time_verification_status = p_decision,
      reviewed_by = _admin.id,
      reviewed_at = now(),
      review_notes = COALESCE(p_notes, review_notes)
  WHERE event_id = p_event_id;

  -- Audit log entry
  INSERT INTO device_audit_log (event_type, student_id, performed_by, details)
  VALUES (
    'attendance_time_reviewed',
    _log.student_id,
    _admin.id,
    jsonb_build_object(
      'event_id', p_event_id,
      'decision', p_decision,
      'previous_status', _log.time_verification_status,
      'time_source', _log.time_source,
      'notes', p_notes
    )
  );

  RETURN jsonb_build_object(
    'ok', true,
    'event_id', p_event_id,
    'decision', p_decision,
    'reviewed_at', now()
  );
END;
$$;

-- ── 5. Admin RPC: Get Attendance Review Queue ───────────────────────────────
CREATE OR REPLACE FUNCTION admin_get_pending_attendance_reviews(
  p_token uuid,
  p_status text DEFAULT 'pending_review',
  p_limit integer DEFAULT 50
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _records jsonb;
BEGIN
  -- Verify admin/manager session
  SELECT * INTO _sess FROM active_sessions WHERE token = p_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized: invalid or expired session');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied');
  END IF;

  SELECT jsonb_agg(r ORDER BY r->>'terminal_saved_at' DESC) INTO _records
  FROM (
    SELECT jsonb_build_object(
      'id', l.id,
      'event_id', l.event_id,
      'student_id', l.student_id,
      'student_name', p.full_name,
      'matric_number', p.matric_number,
      'terminal_id', l.terminal_id,
      'terminal_name', d.name,
      'session_id', l.session_id,
      'terminal_saved_at', l.terminal_saved_at,
      'phone_attendance_time', l.phone_attendance_time,
      'server_received_at', l.server_received_at,
      'time_source', l.time_source,
      'time_verification_status', l.time_verification_status,
      'clock_skew_seconds', CASE
        WHEN l.terminal_saved_at IS NOT NULL AND l.phone_attendance_time IS NOT NULL
        THEN round(abs(extract(epoch from (l.terminal_saved_at - l.phone_attendance_time))))
        ELSE null
      END,
      'reviewed_by', l.reviewed_by,
      'reviewer_name', ap.full_name,
      'reviewed_at', l.reviewed_at,
      'review_notes', l.review_notes
    ) AS r
    FROM attendance_logs l
    LEFT JOIN profiles p ON p.id = l.student_id
    LEFT JOIN profiles ap ON ap.id = l.reviewed_by
    LEFT JOIN devices d ON d.device_id = l.terminal_id
    WHERE (p_status IS NULL OR p_status = 'all' OR l.time_verification_status = p_status)
      AND l.method::text = 'ble_offline_signed'
    ORDER BY l.terminal_saved_at DESC NULLS LAST
    LIMIT LEAST(p_limit, 200)
  ) sub;

  RETURN jsonb_build_object('ok', true, 'records', COALESCE(_records, '[]'::jsonb));
END;
$$;

