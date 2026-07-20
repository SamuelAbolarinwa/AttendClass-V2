-- =============================================================================
-- 0009: Admin Dashboard - Settings, RLS Security, and RPCs
-- =============================================================================

SET search_path TO public, extensions;

-- ── 1. App Settings Table ───────────────────────────────────────────────────
CREATE TABLE app_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tracking_period_end_date date,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Ensure it's a singleton
CREATE UNIQUE INDEX app_settings_singleton_idx ON app_settings ((true));

COMMENT ON TABLE app_settings IS 'Global application configurations (singleton).';
COMMENT ON COLUMN app_settings.tracking_period_end_date IS 'Optional cutoff date for calculating attendance metrics. If null, calculations run up to today.';

ALTER TABLE app_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_settings_select ON app_settings FOR SELECT USING (true);

-- Insert the default singleton row
INSERT INTO app_settings (tracking_period_end_date) VALUES (null);

-- ── 2. Add manual_admin to enum ─────────────────────────────────────────────
ALTER TYPE attendance_method ADD VALUE IF NOT EXISTS 'manual_admin';

-- ── 3. Secure Write Access for Admin Data ───────────────────────────────────
-- Revoke all write operations from anon and authenticated on these tables
REVOKE INSERT, UPDATE, DELETE ON attendance_logs FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON cancelled_days FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON app_settings FROM anon, authenticated;

-- (SELECT remains permissive as defined in their existing policies)

-- ── 4. RPC: platform_toggle_attendance ──────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_toggle_attendance(p_token uuid, p_student_id uuid, p_date date, p_present boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean OR _sess->>'role' != 'administrator' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden');
  END IF;

  IF p_present THEN
    -- Insert if it doesn't already exist for that day
    IF NOT EXISTS (SELECT 1 FROM attendance_logs WHERE student_id = p_student_id AND verified_at::date = p_date) THEN
      INSERT INTO attendance_logs (student_id, method, verified_at)
      VALUES (p_student_id, 'manual_admin', p_date + time '08:00:00');
    END IF;
  ELSE
    -- Delete all logs for that student on that day
    DELETE FROM attendance_logs 
    WHERE student_id = p_student_id AND verified_at::date = p_date;
  END IF;

  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── 5. RPC: platform_upsert_cancelled_day ───────────────────────────────────
CREATE OR REPLACE FUNCTION platform_upsert_cancelled_day(p_token uuid, p_dates date[], p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _d date;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean OR _sess->>'role' != 'administrator' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden');
  END IF;

  FOREACH _d IN ARRAY p_dates LOOP
    INSERT INTO cancelled_days (cancelled_date, reason)
    VALUES (_d, p_reason)
    ON CONFLICT (cancelled_date) DO UPDATE SET reason = EXCLUDED.reason;
  END LOOP;

  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── 6. RPC: platform_delete_cancelled_day ───────────────────────────────────
CREATE OR REPLACE FUNCTION platform_delete_cancelled_day(p_token uuid, p_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean OR _sess->>'role' != 'administrator' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden');
  END IF;

  DELETE FROM cancelled_days WHERE id = p_id;
  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── 7. RPC: platform_update_settings ────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_update_settings(p_token uuid, p_tracking_period_end_date date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean OR _sess->>'role' != 'administrator' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden');
  END IF;

  UPDATE app_settings 
  SET tracking_period_end_date = p_tracking_period_end_date, updated_at = now()
  WHERE true; -- updates the singleton row

  RETURN jsonb_build_object('ok', true);
END; $$;

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
