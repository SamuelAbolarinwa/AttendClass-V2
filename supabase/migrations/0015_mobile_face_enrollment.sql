-- =============================================================================
-- 0015: Mobile Face Enrollment & Multi-model Support
-- =============================================================================

SET search_path TO public, extensions;

-- ── 1. Drop the existing index before altering the column ───────────────────
DROP INDEX IF EXISTS idx_face_enrollments_embedding;

-- ── 2. Alter embedding column to be unconstrained ───────────────────────────
-- This allows storing 128-d (face-api.js) and 192-d (mobilefacenet) vectors in the same column.
ALTER TABLE face_enrollments ALTER COLUMN embedding TYPE vector;

-- ── 3. Update platform_enroll_face ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_enroll_face(p_token uuid, p_embedding vector, p_model_version text DEFAULT 'face-api-0.22')
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

  -- Deactivate any prior enrollments for this account FOR THIS SPECIFIC MODEL VERSION
  UPDATE face_enrollments 
  SET active = false 
  WHERE account_id = _acct_id AND model_version = p_model_version AND active = true;

  -- Insert the new enrollment
  INSERT INTO face_enrollments (account_id, embedding, model_version, active)
  VALUES (_acct_id, p_embedding, p_model_version, true);

  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── 4. Update platform_verify_face ──────────────────────────────────────────
-- Incorporates a dynamic similarity threshold depending on the model_version.
CREATE OR REPLACE FUNCTION platform_verify_face(p_token uuid, p_embedding vector, p_model_version text DEFAULT 'face-api-0.22')
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _acct_id uuid;
  _stored vector;
  _distance float;
  _similarity float;
  _threshold float;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('match', false, 'error', 'Invalid or expired session');
  END IF;

  _acct_id := (_sess->>'account_id')::uuid;

  SELECT embedding INTO _stored
  FROM face_enrollments
  WHERE account_id = _acct_id AND model_version = p_model_version AND active = true
  ORDER BY enrolled_at DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('match', false, 'error', 'No active face enrollment found for this platform/model');
  END IF;

  -- <=> is the vector cosine distance operator in pgvector.
  -- Cosine similarity is 1 - cosine_distance.
  _distance := (p_embedding <=> _stored);
  _similarity := 1.0 - _distance;

  -- Determine threshold based on model version. 
  -- Note: These are starting estimates and need empirical tuning after real test captures!
  IF p_model_version = 'mobilefacenet-mobile-v1' THEN
    _threshold := 0.60; -- Estimate for mobilefacenet
  ELSE
    _threshold := 0.55; -- Original estimate for face-api-0.22
  END IF;

  IF _similarity >= _threshold THEN
    RETURN jsonb_build_object('match', true, 'similarity', _similarity);
  ELSE
    RETURN jsonb_build_object('match', false, 'similarity', _similarity);
  END IF;
END; $$;

-- ── 5. Update platform_has_active_enrollment ────────────────────────────────
-- Ensure we check for active enrollment matching the required model version
CREATE OR REPLACE FUNCTION platform_has_active_enrollment(p_token uuid, p_model_version text DEFAULT 'face-api-0.22')
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
      AND model_version = p_model_version
      AND active = true
  ) INTO _has_active;

  RETURN jsonb_build_object('ok', true, 'has_active', _has_active);
END; $$;
