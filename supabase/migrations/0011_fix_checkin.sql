-- =============================================================================
-- 0011: Fix Check-In RPCs
-- =============================================================================
SET search_path TO public, extensions;

-- ── platform_verify_face ────────────────────────────────────────────────────
-- Verifies the session token, looks up the active face enrollment for the account,
-- and computes cosine similarity against the provided vector.
-- A similarity >= 0.55 is considered a match (tunable threshold for face-api.js).
CREATE OR REPLACE FUNCTION platform_verify_face(p_token uuid, p_embedding vector(128))
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _acct_id uuid;
  _stored vector(128);
  _distance float;
  _similarity float;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('match', false, 'error', 'Invalid or expired session');
  END IF;

  _acct_id := (_sess->>'account_id')::uuid;

  SELECT embedding INTO _stored
  FROM face_enrollments
  WHERE account_id = _acct_id
  ORDER BY enrolled_at DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('match', false, 'error', 'No active face enrollment found');
  END IF;

  -- <=> is the vector cosine distance operator in pgvector.
  -- Cosine similarity is 1 - cosine_distance.
  _distance := (p_embedding <=> _stored);
  _similarity := 1.0 - _distance;

  IF _similarity >= 0.55 THEN
    RETURN jsonb_build_object('match', true, 'similarity', _similarity);
  ELSE
    RETURN jsonb_build_object('match', false, 'similarity', _similarity);
  END IF;
END; $$;

-- ── platform_log_attendance ─────────────────────────────────────────────────
-- Checks if an attendance_logs row exists for this account today.
-- If so, returns already_logged_today=true.
-- Otherwise, inserts a new log.
CREATE OR REPLACE FUNCTION platform_log_attendance(p_token uuid, p_method text, p_rssi int)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _acct_id uuid;
  _existing_log record;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;

  _acct_id := (_sess->>'account_id')::uuid;

  -- Validate method
  IF p_method != 'face_ble_signed' AND p_method != 'manual_admin' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid attendance method');
  END IF;

  -- Check if already logged today (using database local time / UTC)
  SELECT * INTO _existing_log
  FROM attendance_logs
  WHERE student_id = _acct_id
    AND verified_at::date = now()::date
  LIMIT 1;

  IF FOUND THEN
    RETURN jsonb_build_object(
      'ok', true,
      'already_logged_today', true,
      'logged_at', _existing_log.verified_at
    );
  END IF;

  -- Insert new log
  INSERT INTO attendance_logs (student_id, method, rssi_dbm, verified_at, created_at)
  VALUES (_acct_id, p_method::attendance_method, p_rssi, now(), now());

  RETURN jsonb_build_object('ok', true, 'already_logged_today', false);
END; $$;

-- ── platform_get_my_attendance ──────────────────────────────────────────────
-- Returns the attendance history for the requesting session.
CREATE OR REPLACE FUNCTION platform_get_my_attendance(p_token uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _acct_id uuid;
  _logs jsonb;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;

  _acct_id := (_sess->>'account_id')::uuid;

  SELECT COALESCE(jsonb_agg(row_to_json(a) ORDER BY a.verified_at DESC), '[]'::jsonb)
  INTO _logs
  FROM attendance_logs a
  WHERE a.student_id = _acct_id;

  RETURN jsonb_build_object('ok', true, 'data', _logs);
END; $$;
