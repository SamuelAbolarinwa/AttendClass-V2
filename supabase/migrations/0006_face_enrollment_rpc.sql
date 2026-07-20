-- =============================================================================
-- 0006: Face Enrollment RPC and strict RLS
-- =============================================================================

SET search_path TO public, extensions;

-- ── 1. Rename student_id to account_id ──────────────────────────────────────
ALTER TABLE face_enrollments RENAME COLUMN student_id TO account_id;

-- ── 2. Strict RLS for face_enrollments ──────────────────────────────────────
-- Drop the old permissive policy
DROP POLICY IF EXISTS face_enrollments_permissive ON face_enrollments;

-- Revoke all direct table access from anon and authenticated users
REVOKE ALL ON face_enrollments FROM anon, authenticated;

-- Since the table has RLS enabled (from 0001), with no policies, default deny applies.
-- Only the database owner (which SECURITY DEFINER functions run as) can access it.

-- ── 3. platform_has_active_enrollment ───────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_has_active_enrollment(p_token uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _has_active boolean;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM face_enrollments 
    WHERE account_id = (_sess->>'account_id')::uuid 
      AND active = true
  ) INTO _has_active;

  RETURN jsonb_build_object('ok', true, 'has_active', _has_active);
END; $$;

-- ── 4. platform_enroll_face ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_enroll_face(p_token uuid, p_embedding vector(128))
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _acct_id uuid;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;

  _acct_id := (_sess->>'account_id')::uuid;

  -- Deactivate any prior enrollments for this account
  UPDATE face_enrollments 
  SET active = false 
  WHERE account_id = _acct_id AND active = true;

  -- Insert the new enrollment
  INSERT INTO face_enrollments (account_id, embedding, model_version, active)
  VALUES (_acct_id, p_embedding, 'face-api-0.22', true);

  RETURN jsonb_build_object('ok', true);
END; $$;

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
