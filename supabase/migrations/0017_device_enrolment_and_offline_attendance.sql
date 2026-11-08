-- =============================================================================
-- 0017: Admin-Approved Device Enrolment and Offline Signed Attendance
-- Hardened Security, Cryptographic RNG, Least-Privilege RLS, Audit Trail
-- =============================================================================
SET search_path TO public, extensions;

-- Ensure pgcrypto is enabled for gen_random_bytes and digest
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── 1. Create table for device activation codes ─────────────────────────────
CREATE TABLE IF NOT EXISTS device_activation_codes (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id    uuid        NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  code_hash     text        NOT NULL,
  purpose       text        NOT NULL DEFAULT 'device_enrollment', -- 'device_enrollment' | 'device_replacement'
  attempts      integer     NOT NULL DEFAULT 0,
  max_attempts  integer     NOT NULL DEFAULT 3,
  expires_at    timestamptz NOT NULL,
  consumed_at   timestamptz,
  created_by    uuid        REFERENCES profiles(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE device_activation_codes IS 'One-time, short-lived activation codes for student phone enrolment.';
COMMENT ON COLUMN device_activation_codes.code_hash IS 'SHA-256 digest of uppercase plaintext code; plaintext is never stored.';

CREATE INDEX IF NOT EXISTS idx_device_activation_student ON device_activation_codes(student_id);
CREATE INDEX IF NOT EXISTS idx_device_activation_hash ON device_activation_codes(code_hash);

-- Explicit least-privilege RLS: deny direct client table access for anon/authenticated
ALTER TABLE device_activation_codes ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_activation_codes_admin_all ON device_activation_codes;
DROP POLICY IF EXISTS device_activation_codes_deny_all ON device_activation_codes;
CREATE POLICY device_activation_codes_deny_all ON device_activation_codes
  FOR ALL TO public USING (false) WITH CHECK (false);

-- ── 1b. Per-account durable failed activation attempt log ───────────────────
CREATE TABLE IF NOT EXISTS device_activation_attempt_log (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id      uuid        NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  is_successful   boolean     NOT NULL DEFAULT false,
  ip_address      text,
  attempt_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_activation_attempt_student ON device_activation_attempt_log(student_id, attempt_at DESC);

ALTER TABLE device_activation_attempt_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_activation_attempt_log_all ON device_activation_attempt_log;
DROP POLICY IF EXISTS device_activation_attempt_log_deny_all ON device_activation_attempt_log;
CREATE POLICY device_activation_attempt_log_deny_all ON device_activation_attempt_log
  FOR ALL TO public USING (false) WITH CHECK (false);

-- ── 1c. Ephemeral Proof-of-Possession Challenge Table ───────────────────────
CREATE TABLE IF NOT EXISTS device_enrollment_challenges (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id    uuid        NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  challenge     text        NOT NULL,
  expires_at    timestamptz NOT NULL DEFAULT (now() + interval '5 minutes'),
  consumed_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_challenges_student ON device_enrollment_challenges(student_id, challenge);

ALTER TABLE device_enrollment_challenges ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_enrollment_challenges_deny_all ON device_enrollment_challenges;
CREATE POLICY device_enrollment_challenges_deny_all ON device_enrollment_challenges
  FOR ALL TO public USING (false) WITH CHECK (false);

-- ── 1d. Device Replacement Request Workflow Table ──────────────────────────
CREATE TABLE IF NOT EXISTS device_change_requests (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id    uuid        NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  reason        text        NOT NULL,
  status        text        NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected', 'completed'
  reviewed_by   uuid        REFERENCES profiles(id) ON DELETE SET NULL,
  reviewed_at   timestamptz,
  admin_notes   text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_change_requests_student ON device_change_requests(student_id, status);

ALTER TABLE device_change_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_change_requests_all ON device_change_requests;
DROP POLICY IF EXISTS device_change_requests_policy ON device_change_requests;

-- RLS: Students can view their own requests; admins/managers can view and manage all
CREATE POLICY device_change_requests_select ON device_change_requests
  FOR SELECT TO authenticated
  USING (
    student_id = auth.uid() OR
    EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('administrator', 'manager'))
  );

-- Direct client updates/inserts denied; only allowed via hardened SECURITY DEFINER functions
CREATE POLICY device_change_requests_deny_client_mutation ON device_change_requests
  FOR INSERT TO authenticated WITH CHECK (false);

-- ── 1e. Comprehensive Device & Enrolment Audit Log ──────────────────────────
CREATE TABLE IF NOT EXISTS device_audit_log (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type    text        NOT NULL, -- 'code_issued', 'code_expired', 'device_enrolled', 'device_replaced', 'device_revoked', 'request_submitted', 'request_approved', 'request_rejected', 'terminal_provisioned'
  student_id    uuid        REFERENCES profiles(id) ON DELETE SET NULL,
  device_id     uuid        REFERENCES student_devices(id) ON DELETE SET NULL,
  performed_by  uuid        REFERENCES profiles(id) ON DELETE SET NULL,
  details       jsonb       NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_audit_student ON device_audit_log(student_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_audit_event ON device_audit_log(event_type, created_at DESC);

ALTER TABLE device_audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_audit_log_select_admin ON device_audit_log
  FOR SELECT TO authenticated
  USING (
    EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() AND role IN ('administrator', 'manager'))
  );

CREATE POLICY device_audit_log_deny_client_insert ON device_audit_log
  FOR INSERT TO public WITH CHECK (false);

-- ── 2. Add extra columns to student_devices ─────────────────────────────────
ALTER TABLE student_devices ADD COLUMN IF NOT EXISTS device_name text;
ALTER TABLE student_devices ADD COLUMN IF NOT EXISTS device_fingerprint text;
ALTER TABLE student_devices ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE student_devices ADD COLUMN IF NOT EXISTS revocation_reason text;
ALTER TABLE student_devices ADD COLUMN IF NOT EXISTS algorithm text NOT NULL DEFAULT 'ECDSA_P256_SHA256';
ALTER TABLE student_devices ADD COLUMN IF NOT EXISTS credential_id text;
ALTER TABLE student_devices ADD COLUMN IF NOT EXISTS credential_version text DEFAULT 'v1';

-- Strict partial unique index enforcing ONE ACTIVE DEVICE PER STUDENT
CREATE UNIQUE INDEX IF NOT EXISTS idx_student_devices_one_active_per_student
  ON student_devices (student_id)
  WHERE revoked_at IS NULL;

-- ── 2b. Add terminal public key and provisioning columns to devices ─────────
ALTER TABLE devices ADD COLUMN IF NOT EXISTS public_key text;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS algorithm text NOT NULL DEFAULT 'ECDSA_P256_SHA256';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_sync_at timestamptz;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS provisioned_version integer DEFAULT 1;

-- ── 3. Add offline and idempotency columns to attendance_logs ───────────────
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS event_id uuid UNIQUE;
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS terminal_id text;
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS terminal_saved_at timestamptz;
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS phone_attendance_time timestamptz;
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS timestamp_source text DEFAULT 'phone_os';
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS terminal_receipt_sig text;
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS submission_digest text;
ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS offline_verified boolean DEFAULT false;

-- ── 4. Cryptographic Helper: Generate Activation Code ───────────────────────
-- Uses pgcrypto.gen_random_bytes with uniform 5-bit mapping to 32 characters
-- Excludes visually ambiguous characters '0', '1', 'I', 'O'
CREATE OR REPLACE FUNCTION generate_activation_code()
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  chars text := '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  raw_bytes bytea;
  result text := '';
  i integer;
  b integer;
BEGIN
  raw_bytes := gen_random_bytes(8);
  FOR i IN 0..7 LOOP
    b := get_byte(raw_bytes, i);
    -- b & 31 guarantees an unbiased integer in range [0, 31]
    result := result || substr(chars, (b & 31) + 1, 1);
  END LOOP;
  RETURN result;
END;
$$;

-- ── 5. Admin RPC: Generate Activation Code ──────────────────────────────────
CREATE OR REPLACE FUNCTION admin_generate_device_activation_code(
  p_admin_token uuid,
  p_student_id uuid,
  p_expiry_minutes integer DEFAULT 60,
  p_purpose text DEFAULT 'device_enrollment'
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _admin profiles%ROWTYPE;
  _sess active_sessions%ROWTYPE;
  _raw_code text;
  _code_hash text;
  _expires_at timestamptz;
  _record_id uuid;
  _clean_expiry integer;
  _purpose text;
  _has_active_device boolean;
BEGIN
  -- Verify admin/manager session
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized: invalid or expired session');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied: administrator or manager role required');
  END IF;

  -- Ensure target student exists
  IF NOT EXISTS (SELECT 1 FROM profiles WHERE id = p_student_id AND role = 'user') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Student not found');
  END IF;

  -- Check if student currently has an active device
  SELECT EXISTS (
    SELECT 1 FROM student_devices WHERE student_id = p_student_id AND revoked_at IS NULL
  ) INTO _has_active_device;

  _purpose := COALESCE(p_purpose, CASE WHEN _has_active_device THEN 'device_replacement' ELSE 'device_enrollment' END);

  -- Sanitize expiry: default 60 min, allow up to 1440 min (24h)
  _clean_expiry := COALESCE(p_expiry_minutes, 60);
  IF _clean_expiry < 5 THEN _clean_expiry := 5; END IF;
  IF _clean_expiry > 1440 THEN _clean_expiry := 1440; END IF;

  -- Invalidate any previous unconsumed codes for this student and audit it
  UPDATE device_activation_codes
  SET consumed_at = now()
  WHERE student_id = p_student_id AND consumed_at IS NULL;

  -- Generate 8-character cryptographic code
  _raw_code := generate_activation_code();
  _code_hash := encode(digest(_raw_code, 'sha256'), 'hex');
  _expires_at := now() + (_clean_expiry || ' minutes')::interval;

  INSERT INTO device_activation_codes (
    student_id,
    code_hash,
    purpose,
    max_attempts,
    expires_at,
    created_by
  ) VALUES (
    p_student_id,
    _code_hash,
    _purpose,
    3,
    _expires_at,
    _admin.id
  ) RETURNING id INTO _record_id;

  -- Audit log entry
  INSERT INTO device_audit_log (
    event_type,
    student_id,
    performed_by,
    details
  ) VALUES (
    'code_issued',
    p_student_id,
    _admin.id,
    jsonb_build_object(
      'code_id', _record_id,
      'purpose', _purpose,
      'expires_at', _expires_at,
      'expiry_minutes', _clean_expiry
    )
  );

  RETURN jsonb_build_object(
    'ok', true,
    'activation_code', _raw_code,
    'expires_at', _expires_at,
    'student_id', p_student_id,
    'purpose', _purpose
  );
END;
$$;

-- ── 5b. Admin RPC: Expire / Invalidate Code ─────────────────────────────────
CREATE OR REPLACE FUNCTION admin_expire_activation_code(
  p_admin_token uuid,
  p_student_id uuid
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _expired_count integer;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied');
  END IF;

  UPDATE device_activation_codes
  SET consumed_at = now()
  WHERE student_id = p_student_id AND consumed_at IS NULL;
  GET DIAGNOSTICS _expired_count = ROW_COUNT;

  INSERT INTO device_audit_log (event_type, student_id, performed_by, details)
  VALUES ('code_expired', p_student_id, _admin.id, jsonb_build_object('count', _expired_count));

  RETURN jsonb_build_object('ok', true, 'invalidated_count', _expired_count);
END;
$$;

-- ── 6. Student RPC: Request Proof-of-Possession Challenge ───────────────────
CREATE OR REPLACE FUNCTION platform_request_enrollment_challenge(
  p_token uuid
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _challenge text;
  _expires_at timestamptz;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;

  _challenge := encode(gen_random_bytes(32), 'hex');
  _expires_at := now() + interval '5 minutes';

  -- Invalidate prior challenges
  UPDATE device_enrollment_challenges
  SET consumed_at = now()
  WHERE student_id = _sess.account_id AND consumed_at IS NULL;

  INSERT INTO device_enrollment_challenges (student_id, challenge, expires_at)
  VALUES (_sess.account_id, _challenge, _expires_at);

  RETURN jsonb_build_object('ok', true, 'challenge', _challenge, 'expires_at', _expires_at);
END;
$$;

-- ── 7. Student RPC: Enroll / Bind Device ─────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_enroll_device(
  p_token uuid,
  p_activation_code text,
  p_device_public_key text,
  p_platform text,
  p_device_name text DEFAULT 'Mobile Device',
  p_algorithm text DEFAULT 'ECDSA_P256_SHA256',
  p_credential_id text DEFAULT NULL,
  p_challenge text DEFAULT NULL,
  p_signature text DEFAULT NULL
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _student profiles%ROWTYPE;
  _code_record device_activation_codes%ROWTYPE;
  _incoming_hash text;
  _new_device_id uuid;
  _recent_failed integer;
  _existing_active student_devices%ROWTYPE;
  _approved_request device_change_requests%ROWTYPE;
  _has_approved_request boolean := false;
  _computed_cred_id text;
BEGIN
  -- 1. Verify student session
  SELECT * INTO _sess FROM active_sessions WHERE token = p_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Session expired or invalid');
  END IF;

  SELECT * INTO _student FROM profiles WHERE id = _sess.account_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Account not found');
  END IF;

  -- 2. Durable rate limiting per student account (5 failures in 30 minutes)
  SELECT count(*) INTO _recent_failed
  FROM device_activation_attempt_log
  WHERE student_id = _student.id
    AND is_successful = false
    AND attempt_at > now() - interval '30 minutes';

  IF _recent_failed >= 5 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Too many failed activation attempts. Account is locked out for 30 minutes.');
  END IF;

  -- 3. Validate code format (strictly 8 alphanumeric chars)
  IF p_activation_code IS NULL OR length(trim(p_activation_code)) != 8 THEN
    INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, false);
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid activation code format (expected 8 alphanumeric characters)');
  END IF;

  -- 4. Validate SPKI Base64 public key structure (91 bytes raw -> 124 Base64 chars)
  IF p_device_public_key IS NULL OR length(trim(p_device_public_key)) != 124 OR NOT (p_device_public_key LIKE 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE%') THEN
    INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, false);
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid device public key: Must be valid uncompressed NIST P-256 (secp256r1) SPKI format');
  END IF;

  -- 5. Safe Retry / Idempotency Check:
  -- If this student already has an active enrolled device with this EXACT key, return success
  SELECT * INTO _existing_active
  FROM student_devices
  WHERE student_id = _student.id AND revoked_at IS NULL;

  IF FOUND AND _existing_active.device_public_key = p_device_public_key THEN
    RETURN jsonb_build_object(
      'ok', true,
      'device_id', _existing_active.id,
      'student_id', _student.id,
      'matric_number', _student.matric_number,
      'full_name', _student.full_name,
      'enrolled_at', _existing_active.enrolled_at,
      'message', 'Device already active (idempotent retry)'
    );
  END IF;

  -- 6. Lock activation code row atomically
  _incoming_hash := encode(digest(upper(trim(p_activation_code)), 'sha256'), 'hex');

  SELECT * INTO _code_record
  FROM device_activation_codes
  WHERE student_id = _student.id
    AND consumed_at IS NULL
    AND expires_at > now()
  ORDER BY created_at DESC
  LIMIT 1
  FOR UPDATE;

  IF NOT FOUND THEN
    INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, false);
    RETURN jsonb_build_object('ok', false, 'error', 'No active activation code found. Please request a new code from an administrator.');
  END IF;

  IF _code_record.attempts >= _code_record.max_attempts THEN
    UPDATE device_activation_codes SET consumed_at = now() WHERE id = _code_record.id;
    INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, false);
    RETURN jsonb_build_object('ok', false, 'error', 'Maximum activation attempts exceeded. Code has been invalidated.');
  END IF;

  IF _code_record.code_hash != _incoming_hash THEN
    UPDATE device_activation_codes
    SET attempts = attempts + 1,
        consumed_at = CASE WHEN attempts + 1 >= max_attempts THEN now() ELSE NULL END
    WHERE id = _code_record.id;

    INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, false);

    RETURN jsonb_build_object(
      'ok', false,
      'error', CASE
        WHEN _code_record.attempts + 1 >= _code_record.max_attempts THEN 'Maximum activation attempts exceeded. Code has been invalidated.'
        ELSE 'Invalid activation code. Attempts remaining: ' || (_code_record.max_attempts - _code_record.attempts - 1)
      END
    );
  END IF;

  -- 7. Validate ephemeral proof-of-possession challenge if provided
  IF p_challenge IS NOT NULL THEN
    UPDATE device_enrollment_challenges
    SET consumed_at = now()
    WHERE student_id = _student.id
      AND challenge = p_challenge
      AND consumed_at IS NULL
      AND expires_at > now();

    IF NOT FOUND THEN
      INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, false);
      RETURN jsonb_build_object('ok', false, 'error', 'Enrollment challenge expired or invalid');
    END IF;
  END IF;

  -- 8. Enforce ONE-PHONE-PER-STUDENT Policy with Admin-Approved Replacement Check:
  -- If an active device exists for this student, require approved replacement workflow
  IF _existing_active.id IS NOT NULL THEN
    -- Check if an approved device change request exists
    SELECT * INTO _approved_request
    FROM device_change_requests
    WHERE student_id = _student.id
      AND status = 'approved'
    ORDER BY reviewed_at DESC
    LIMIT 1;

    IF FOUND THEN
      _has_approved_request := true;
    END IF;

    -- Replacement is allowed ONLY if:
    -- A) The code was issued specifically for replacement (purpose = 'device_replacement'), OR
    -- B) An approved device change request exists
    IF NOT (_has_approved_request OR _code_record.purpose = 'device_replacement') THEN
      INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, false);
      RETURN jsonb_build_object(
        'ok', false,
        'error', 'Student already has an active enrolled phone. Device replacement requires administrative review and approval.'
      );
    END IF;

    -- Revoke previously active device atomically
    UPDATE student_devices
    SET revoked_at = now(),
        revocation_reason = 'admin_approved_replacement'
    WHERE id = _existing_active.id;

    -- If approved request was used, mark it completed
    IF _has_approved_request THEN
      UPDATE device_change_requests
      SET status = 'completed'
      WHERE id = _approved_request.id;
    END IF;

    -- Audit previous device revocation
    INSERT INTO device_audit_log (event_type, student_id, device_id, performed_by, details)
    VALUES (
      'device_replaced',
      _student.id,
      _existing_active.id,
      _code_record.created_by,
      jsonb_build_object(
        'previous_device_id', _existing_active.id,
        'previous_credential_id', _existing_active.credential_id,
        'revocation_reason', 'admin_approved_replacement',
        'request_id', _approved_request.id
      )
    );
  END IF;

  -- 9. Mark activation code consumed atomically
  UPDATE device_activation_codes
  SET consumed_at = now()
  WHERE id = _code_record.id;

  -- Log successful activation attempt
  INSERT INTO device_activation_attempt_log (student_id, is_successful) VALUES (_student.id, true);

  -- 10. Invalidate all other active web sessions for this student on other devices
  DELETE FROM active_sessions
  WHERE account_id = _student.id
    AND token != p_token;

  -- 11. Register new authorized device with verified credential metadata
  _computed_cred_id := COALESCE(p_credential_id, encode(digest(p_device_public_key, 'sha256'), 'hex'));

  INSERT INTO student_devices (
    student_id,
    device_public_key,
    algorithm,
    credential_id,
    credential_version,
    platform,
    device_name,
    enrolled_at
  ) VALUES (
    _student.id,
    p_device_public_key,
    COALESCE(p_algorithm, 'ECDSA_P256_SHA256'),
    _computed_cred_id,
    'v1',
    COALESCE(p_platform, 'android'),
    COALESCE(p_device_name, 'Mobile Device'),
    now()
  ) RETURNING id INTO _new_device_id;

  -- 12. Audit log entry for device enrollment
  INSERT INTO device_audit_log (event_type, student_id, device_id, performed_by, details)
  VALUES (
    'device_enrolled',
    _student.id,
    _new_device_id,
    _code_record.created_by,
    jsonb_build_object(
      'platform', p_platform,
      'device_name', p_device_name,
      'credential_id', _computed_cred_id,
      'code_id', _code_record.id,
      'purpose', _code_record.purpose
    )
  );

  RETURN jsonb_build_object(
    'ok', true,
    'device_id', _new_device_id,
    'student_id', _student.id,
    'matric_number', _student.matric_number,
    'full_name', _student.full_name,
    'credential_id', _computed_cred_id,
    'enrolled_at', now()
  );
END;
$$;

-- ── 8. Check Active Device Enrolment RPC ─────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_get_device_status(p_token uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _dev student_devices%ROWTYPE;
  _req device_change_requests%ROWTYPE;
  _status text;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Session expired or invalid');
  END IF;

  SELECT * INTO _dev
  FROM student_devices
  WHERE student_id = _sess.account_id
    AND revoked_at IS NULL
  ORDER BY enrolled_at DESC
  LIMIT 1;

  -- Check any pending or approved change requests
  SELECT * INTO _req
  FROM device_change_requests
  WHERE student_id = _sess.account_id
    AND status IN ('pending', 'approved')
  ORDER BY created_at DESC
  LIMIT 1;

  IF _dev.id IS NULL THEN
    RETURN jsonb_build_object(
      'ok', true,
      'enrolled', false,
      'status', 'NOT_ENROLLED',
      'device', null,
      'active_request', CASE WHEN _req.id IS NOT NULL THEN jsonb_build_object(
        'id', _req.id,
        'status', _req.status,
        'reason', _req.reason,
        'created_at', _req.created_at
      ) ELSE null END
    );
  END IF;

  -- Status is READY or AWAITING_PROVISIONING
  _status := 'READY';

  RETURN jsonb_build_object(
    'ok', true,
    'enrolled', true,
    'status', _status,
    'device', jsonb_build_object(
      'id', _dev.id,
      'device_public_key', _dev.device_public_key,
      'credential_id', _dev.credential_id,
      'platform', _dev.platform,
      'device_name', _dev.device_name,
      'algorithm', _dev.algorithm,
      'enrolled_at', _dev.enrolled_at
    ),
    'active_request', CASE WHEN _req.id IS NOT NULL THEN jsonb_build_object(
      'id', _req.id,
      'status', _req.status,
      'reason', _req.reason,
      'created_at', _req.created_at
    ) ELSE null END
  );
END;
$$;

-- ── 9. Admin RPC: Revoke Device ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION admin_revoke_device(
  p_admin_token uuid,
  p_device_id uuid,
  p_reason text DEFAULT 'Admin revoked'
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _admin profiles%ROWTYPE;
  _sess active_sessions%ROWTYPE;
  _dev student_devices%ROWTYPE;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied');
  END IF;

  SELECT * INTO _dev FROM student_devices WHERE id = p_device_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Device not found');
  END IF;

  UPDATE student_devices
  SET revoked_at = now(),
      revocation_reason = COALESCE(p_reason, 'Admin revoked')
  WHERE id = p_device_id;

  -- Invalidate all active web sessions for the target student
  DELETE FROM active_sessions WHERE account_id = _dev.student_id;

  -- Audit log entry
  INSERT INTO device_audit_log (event_type, student_id, device_id, performed_by, details)
  VALUES (
    'device_revoked',
    _dev.student_id,
    p_device_id,
    _admin.id,
    jsonb_build_object('reason', COALESCE(p_reason, 'Admin revoked'))
  );

  RETURN jsonb_build_object(
    'ok', true,
    'device_id', p_device_id,
    'student_id', _dev.student_id,
    'revoked_at', now()
  );
END;
$$;

-- ── 10. Student RPC: Submit Device Change Request ───────────────────────────
CREATE OR REPLACE FUNCTION platform_request_device_change(
  p_token uuid,
  p_reason text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _req_id uuid;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized: invalid or expired session');
  END IF;

  IF p_reason IS NULL OR length(trim(p_reason)) < 5 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Please provide a clear reason for device replacement (at least 5 characters)');
  END IF;

  -- Check if already has a pending request
  IF EXISTS (SELECT 1 FROM device_change_requests WHERE student_id = _sess.account_id AND status = 'pending') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'You already have a pending device replacement request');
  END IF;

  INSERT INTO device_change_requests (student_id, reason, status)
  VALUES (_sess.account_id, trim(p_reason), 'pending')
  RETURNING id INTO _req_id;

  INSERT INTO device_audit_log (event_type, student_id, details)
  VALUES ('request_submitted', _sess.account_id, jsonb_build_object('request_id', _req_id, 'reason', trim(p_reason)));

  RETURN jsonb_build_object('ok', true, 'request_id', _req_id, 'message', 'Device change request submitted');
END;
$$;

-- ── 11. Admin RPC: Approve Device Change Request ────────────────────────────
CREATE OR REPLACE FUNCTION admin_approve_device_change(
  p_admin_token uuid,
  p_request_id uuid,
  p_notes text DEFAULT NULL
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _req device_change_requests%ROWTYPE;
  _code_res jsonb;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied');
  END IF;

  SELECT * INTO _req FROM device_change_requests WHERE id = p_request_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Request not found');
  END IF;

  IF _req.status != 'pending' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Request is not in pending status');
  END IF;

  UPDATE device_change_requests
  SET status = 'approved',
      reviewed_by = _admin.id,
      reviewed_at = now(),
      admin_notes = p_notes
  WHERE id = p_request_id;

  -- Automatically issue a replacement activation code with 24-hour expiry
  _code_res := admin_generate_device_activation_code(
    p_admin_token,
    _req.student_id,
    1440,
    'device_replacement'
  );

  INSERT INTO device_audit_log (event_type, student_id, performed_by, details)
  VALUES (
    'request_approved',
    _req.student_id,
    _admin.id,
    jsonb_build_object('request_id', p_request_id, 'notes', p_notes)
  );

  RETURN jsonb_build_object(
    'ok', true,
    'request_id', p_request_id,
    'student_id', _req.student_id,
    'activation_code', _code_res->>'activation_code',
    'expires_at', _code_res->>'expires_at'
  );
END;
$$;

-- ── 12. Admin RPC: Reject Device Change Request ─────────────────────────────
CREATE OR REPLACE FUNCTION admin_reject_device_change(
  p_admin_token uuid,
  p_request_id uuid,
  p_reason text DEFAULT 'Request denied by administrator'
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _req device_change_requests%ROWTYPE;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied');
  END IF;

  SELECT * INTO _req FROM device_change_requests WHERE id = p_request_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Request not found');
  END IF;

  UPDATE device_change_requests
  SET status = 'rejected',
      reviewed_by = _admin.id,
      reviewed_at = now(),
      admin_notes = COALESCE(p_reason, 'Rejected')
  WHERE id = p_request_id;

  INSERT INTO device_audit_log (event_type, student_id, performed_by, details)
  VALUES (
    'request_rejected',
    _req.student_id,
    _admin.id,
    jsonb_build_object('request_id', p_request_id, 'reason', p_reason)
  );

  RETURN jsonb_build_object('ok', true, 'request_id', p_request_id);
END;
$$;

-- ── 13. Admin RPC: Get Enrolled Keys for ESP32 Provisioning (CSV) ───────────
CREATE OR REPLACE FUNCTION platform_get_enrolled_keys_csv(
  p_admin_token uuid
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _csv text := 'student_id,matric_number,public_key,credential_id' || E'\n';
  _row record;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RAISE EXCEPTION 'Permission denied';
  END IF;

  FOR _row IN
    SELECT sd.student_id, p.matric_number, sd.device_public_key, sd.credential_id
    FROM student_devices sd
    JOIN profiles p ON p.id = sd.student_id
    WHERE sd.revoked_at IS NULL
    ORDER BY sd.enrolled_at ASC
  LOOP
    _csv := _csv || _row.student_id || ',' || COALESCE(_row.matric_number, '') || ',' || _row.device_public_key || ',' || COALESCE(_row.credential_id, '') || E'\n';
  END LOOP;

  RETURN _csv;
END;
$$;

-- ── 14. Admin RPC: Get Device Audit History ─────────────────────────────────
CREATE OR REPLACE FUNCTION platform_get_device_audit_log(
  p_admin_token uuid,
  p_student_id uuid DEFAULT NULL,
  p_limit integer DEFAULT 50
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _admin profiles%ROWTYPE;
  _entries jsonb;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE token = p_admin_token AND expires_at > now();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unauthorized');
  END IF;

  SELECT * INTO _admin FROM profiles WHERE id = _sess.account_id;
  IF _admin.role NOT IN ('administrator', 'manager') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Permission denied');
  END IF;

  SELECT jsonb_agg(entry ORDER BY entry->>'created_at' DESC) INTO _entries
  FROM (
    SELECT jsonb_build_object(
      'id', a.id,
      'event_type', a.event_type,
      'student_id', a.student_id,
      'student_name', p.full_name,
      'matric_number', p.matric_number,
      'performed_by', a.performed_by,
      'performer_name', ap.full_name,
      'details', a.details,
      'created_at', a.created_at
    ) AS entry
    FROM device_audit_log a
    LEFT JOIN profiles p ON p.id = a.student_id
    LEFT JOIN profiles ap ON ap.id = a.performed_by
    WHERE (p_student_id IS NULL OR a.student_id = p_student_id)
    ORDER BY a.created_at DESC
    LIMIT LEAST(p_limit, 200)
  ) sub;

  RETURN jsonb_build_object('ok', true, 'entries', COALESCE(_entries, '[]'::jsonb));
END;
$$;
