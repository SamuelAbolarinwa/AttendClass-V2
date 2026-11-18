-- =============================================================================
-- 0019: Terminal Provisioning RPCs, Public Key Registration & Offline Bundles
-- Authoritative server-driven offline terminal provisioning for AttendClass V2
-- =============================================================================
SET search_path TO public, extensions;

-- Ensure provisioned_version exists on devices
ALTER TABLE devices ADD COLUMN IF NOT EXISTS provisioned_version integer DEFAULT 1;

-- ── 1. Admin RPC: Register / Update Terminal Public Key ──────────────────────
CREATE OR REPLACE FUNCTION platform_update_terminal_key(
  p_admin_token uuid,
  p_terminal_id text,
  p_public_key text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _dev devices%ROWTYPE;
  _new_version integer;
  _clean_key text;
BEGIN
  -- 1. Validate session
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized: Invalid or expired admin session');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden: Administrator or manager role required');
  END IF;

  -- 2. Validate clean key
  _clean_key := trim(p_public_key);
  IF _clean_key IS NULL OR length(_clean_key) < 20 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid public key: Public key must be a valid NIST P-256 SPKI Base64 string');
  END IF;

  -- 3. Find terminal device
  SELECT * INTO _dev FROM devices WHERE device_id = trim(p_terminal_id);
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Device not found: No terminal with identifier ' || p_terminal_id);
  END IF;

  _new_version := COALESCE(_dev.provisioned_version, 0) + 1;

  -- 4. Update terminal public key and bump provisioned version
  UPDATE devices
  SET public_key = _clean_key,
      algorithm = 'ECDSA_P256_SHA256',
      provisioned_version = _new_version,
      last_sync_at = now()
  WHERE id = _dev.id;

  -- 5. Record immutable audit log
  INSERT INTO device_audit_log (
    event_type,
    performed_by,
    details,
    created_at
  ) VALUES (
    'terminal_provisioned',
    _admin.id,
    jsonb_build_object(
      'terminal_id', _dev.device_id,
      'action', 'register_public_key',
      'previous_key_set', (_dev.public_key IS NOT NULL),
      'provisioned_version', _new_version
    ),
    now()
  );

  RETURN jsonb_build_object(
    'ok', true,
    'terminal_id', _dev.device_id,
    'public_key', _clean_key,
    'provisioned_version', _new_version
  );
END;
$$;

-- ── 2. Admin RPC: Trigger Reprovisioning at next Wi-Fi connection ─────────────
CREATE OR REPLACE FUNCTION platform_trigger_terminal_reprovision(
  p_admin_token uuid,
  p_terminal_id text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _dev devices%ROWTYPE;
  _new_version integer;
BEGIN
  -- 1. Validate session
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized: Invalid or expired admin session');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden: Administrator or manager role required');
  END IF;

  -- 2. Find terminal device
  SELECT * INTO _dev FROM devices WHERE device_id = trim(p_terminal_id);
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Device not found: No terminal with identifier ' || p_terminal_id);
  END IF;

  _new_version := COALESCE(_dev.provisioned_version, 0) + 1;

  UPDATE devices
  SET provisioned_version = _new_version,
      last_sync_at = now()
  WHERE id = _dev.id;

  -- 3. Record audit log
  INSERT INTO device_audit_log (
    event_type,
    performed_by,
    details,
    created_at
  ) VALUES (
    'terminal_provisioned',
    _admin.id,
    jsonb_build_object(
      'terminal_id', _dev.device_id,
      'action', 'trigger_reprovision',
      'provisioned_version', _new_version
    ),
    now()
  );

  RETURN jsonb_build_object(
    'ok', true,
    'terminal_id', _dev.device_id,
    'provisioned_version', _new_version
  );
END;
$$;

-- ── 3. Admin RPC: Get Complete Terminal Provisioning Bundle ───────────────────
CREATE OR REPLACE FUNCTION platform_get_terminal_provisioning(
  p_admin_token uuid,
  p_terminal_id text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _dev devices%ROWTYPE;
  _open_count integer;
  _active_session record;
  _start_unix bigint;
  _end_unix bigint;
  _computed_end_unix bigint;
  _course_code text;
  _course_id uuid;
  _keys_json jsonb := '[]'::jsonb;
  _enrolled_count integer := 0;
BEGIN
  -- 1. Validate session
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized: Invalid or expired admin session');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden: Administrator or manager role required');
  END IF;

  -- 2. Find terminal device
  SELECT * INTO _dev FROM devices WHERE device_id = trim(p_terminal_id);
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Device not found: No terminal with identifier ' || p_terminal_id);
  END IF;

  -- 3. Count concurrent open sessions for this terminal
  SELECT count(*) INTO _open_count
  FROM attendance_sessions s
  LEFT JOIN schedules sch ON sch.id = s.schedule_id
  WHERE (s.device_id = _dev.id OR sch.device_id = _dev.id)
    AND s.closed_at IS NULL;

  IF _open_count > 1 THEN
    RETURN jsonb_build_object(
      'ok', false,
      'error', 'MULTIPLE_ACTIVE_SESSIONS',
      'message', 'Terminal has multiple concurrent unclosed sessions'
    );
  END IF;

  -- 4. If no open session, return active_session: null and empty keys
  IF _open_count = 0 THEN
    RETURN jsonb_build_object(
      'ok', true,
      'terminal_id', _dev.device_id,
      'name', _dev.name,
      'location', _dev.location,
      'public_key', _dev.public_key,
      'is_active', _dev.is_active,
      'provisioned_version', COALESCE(_dev.provisioned_version, 1),
      'last_sync_at', _dev.last_sync_at,
      'active_session', null,
      'enrolled_keys', '[]'::jsonb,
      'enrolled_count', 0
    );
  END IF;

  -- 5. Open session exists: fetch details
  SELECT
    s.id AS session_id,
    s.opened_at,
    c.id AS course_id,
    c.code AS course_code,
    sch.start_time,
    sch.end_time
  INTO _active_session
  FROM attendance_sessions s
  LEFT JOIN schedules sch ON sch.id = s.schedule_id
  LEFT JOIN courses c ON c.id = sch.course_id
  WHERE (s.device_id = _dev.id OR sch.device_id = _dev.id)
    AND s.closed_at IS NULL
  LIMIT 1;

  _start_unix := EXTRACT(epoch FROM _active_session.opened_at)::bigint;
  _course_code := COALESCE(_active_session.course_code, 'UNKNOWN');
  _course_id := _active_session.course_id;

  -- Compute end_unix in Africa/Lagos (UTC+1)
  IF _active_session.end_time IS NOT NULL THEN
    _computed_end_unix := EXTRACT(
      epoch FROM (
        ((_active_session.opened_at AT TIME ZONE 'Africa/Lagos')::date + _active_session.end_time)
        AT TIME ZONE 'Africa/Lagos'
      )
    )::bigint;

    IF _computed_end_unix > _start_unix THEN
      _end_unix := _computed_end_unix;
    ELSE
      _end_unix := _start_unix + 3600;
    END IF;
  ELSE
    _end_unix := _start_unix + 3600;
  END IF;

  -- 6. Fetch course-enrolled active student keys (capped at 200)
  IF _course_id IS NOT NULL THEN
    WITH distinct_keys AS (
      SELECT DISTINCT ON (sd.student_id)
        sd.student_id,
        COALESCE(p.matric_number, '') AS matric_number,
        sd.device_public_key AS public_key,
        COALESCE(sd.credential_id, '') AS credential_id,
        COALESCE(sd.algorithm, 'ECDSA_P256_SHA256') AS algorithm,
        sd.enrolled_at
      FROM enrollments e
      JOIN profiles p ON p.id = e.student_id
      JOIN student_devices sd ON sd.student_id = e.student_id
      WHERE e.course_id = _course_id
        AND sd.revoked_at IS NULL
      ORDER BY sd.student_id, sd.enrolled_at DESC
    ),
    capped_keys AS (
      SELECT * FROM distinct_keys
      ORDER BY enrolled_at ASC
      LIMIT 200
    )
    SELECT
      COALESCE(jsonb_agg(
        jsonb_build_object(
          'student_id', student_id,
          'matric_number', matric_number,
          'public_key', public_key,
          'credential_id', credential_id,
          'algorithm', algorithm
        )
      ), '[]'::jsonb),
      count(*)
    INTO _keys_json, _enrolled_count
    FROM capped_keys;
  END IF;

  RETURN jsonb_build_object(
    'ok', true,
    'terminal_id', _dev.device_id,
    'name', _dev.name,
    'location', _dev.location,
    'public_key', _dev.public_key,
    'is_active', _dev.is_active,
    'provisioned_version', COALESCE(_dev.provisioned_version, 1),
    'last_sync_at', _dev.last_sync_at,
    'active_session', jsonb_build_object(
      'session_id', _active_session.session_id,
      'course_code', _course_code,
      'start_unix', _start_unix,
      'end_unix', _end_unix
    ),
    'enrolled_keys', _keys_json,
    'enrolled_count', _enrolled_count
  );
END;
$$;
