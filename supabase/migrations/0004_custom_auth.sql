-- =============================================================================
-- 0004: Replace Supabase Auth with custom bcrypt + session token auth
-- =============================================================================
-- Supabase installs pgcrypto in the 'extensions' schema, so we set search_path
-- to find crypt() and gen_salt() without schema-qualifying every call.
SET search_path TO public, extensions;

-- ── 1. Enable pgcrypto ─────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── 2. Decouple profiles from auth.users ────────────────────────────────────
ALTER TABLE profiles DROP CONSTRAINT profiles_id_fkey;
ALTER TABLE profiles ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- ── 3. Add custom auth columns (nullable first for backfill) ────────────────
ALTER TABLE profiles ADD COLUMN identifier text UNIQUE;
ALTER TABLE profiles ADD COLUMN password_hash text;
ALTER TABLE profiles ADD COLUMN must_change_password boolean NOT NULL DEFAULT true;

-- ── 4. Backfill existing rows ───────────────────────────────────────────────
-- Identifier: use matric_number where available, fallback for admin/others
UPDATE profiles SET identifier = matric_number WHERE matric_number IS NOT NULL;
UPDATE profiles
  SET identifier = 'admin@attendclass.local'
  WHERE role = 'administrator' AND matric_number IS NULL AND identifier IS NULL;
UPDATE profiles
  SET identifier = lower(replace(full_name, ' ', '.')) || '@attendclass.local'
  WHERE identifier IS NULL;

-- Password: consistently derived as lowercase(first word of full_name)
UPDATE profiles
  SET password_hash = crypt(lower(split_part(full_name, ' ', 1)), gen_salt('bf'));

-- ── 5. Enforce NOT NULL ─────────────────────────────────────────────────────
ALTER TABLE profiles ALTER COLUMN identifier SET NOT NULL;
ALTER TABLE profiles ALTER COLUMN password_hash SET NOT NULL;

-- ── 6. Drop old column ─────────────────────────────────────────────────────
ALTER TABLE profiles DROP COLUMN IF EXISTS must_reset_password;

-- ── 7. Ensure admin exists (no-op if already backfilled above) ──────────────
INSERT INTO profiles (role, full_name, identifier, password_hash, must_change_password)
VALUES (
  'administrator',
  'Samuel Abolarinwa',
  'admin@attendclass.local',
  crypt('samuel', gen_salt('bf')),
  true
) ON CONFLICT (identifier) DO NOTHING;

-- ── 8. active_sessions table ────────────────────────────────────────────────
CREATE TABLE active_sessions (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid        NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  token      uuid        UNIQUE NOT NULL DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '12 hours')
);

COMMENT ON TABLE active_sessions IS 'Session tokens for custom auth. Expire after 12 hours.';
ALTER TABLE active_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY active_sessions_permissive ON active_sessions FOR ALL USING (true) WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════════════════
-- RPCs (all SECURITY DEFINER with search_path set for pgcrypto access)
-- ═══════════════════════════════════════════════════════════════════════════

-- ── platform_login ──────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_login(p_identifier text, p_password text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _acct  profiles%ROWTYPE;
  _token uuid;
BEGIN
  SELECT * INTO _acct FROM profiles WHERE profiles.identifier = p_identifier;
  IF _acct IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid credentials');
  END IF;
  IF _acct.password_hash != crypt(p_password, _acct.password_hash) THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid credentials');
  END IF;
  INSERT INTO active_sessions (account_id) VALUES (_acct.id) RETURNING token INTO _token;
  RETURN jsonb_build_object(
    'ok', true, 'token', _token,
    'id', _acct.id, 'full_name', _acct.full_name,
    'role', _acct.role, 'must_change_password', _acct.must_change_password,
    'identifier', _acct.identifier
  );
END; $$;

-- ── platform_verify_session ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_verify_session(p_token uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess active_sessions%ROWTYPE;
  _role text;
BEGIN
  SELECT * INTO _sess FROM active_sessions WHERE active_sessions.token = p_token AND expires_at > now();
  IF _sess IS NULL THEN
    RETURN jsonb_build_object('valid', false);
  END IF;
  SELECT role::text INTO _role FROM profiles WHERE id = _sess.account_id;
  RETURN jsonb_build_object('valid', true, 'account_id', _sess.account_id, 'role', _role);
END; $$;

-- ── platform_force_set_password ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_force_set_password(p_token uuid, p_current_password text, p_new_password text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _acct profiles%ROWTYPE;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;
  SELECT * INTO _acct FROM profiles WHERE id = (_sess->>'account_id')::uuid;
  IF _acct.password_hash != crypt(p_current_password, _acct.password_hash) THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Current password is incorrect');
  END IF;
  UPDATE profiles SET password_hash = crypt(p_new_password, gen_salt('bf')), must_change_password = false
    WHERE id = _acct.id;
  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── platform_change_password ────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_change_password(p_token uuid, p_current_password text, p_new_password text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
  _acct profiles%ROWTYPE;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;
  SELECT * INTO _acct FROM profiles WHERE id = (_sess->>'account_id')::uuid;
  IF _acct.password_hash != crypt(p_current_password, _acct.password_hash) THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Current password is incorrect');
  END IF;
  UPDATE profiles SET password_hash = crypt(p_new_password, gen_salt('bf')) WHERE id = _acct.id;
  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── platform_logout ─────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_logout(p_token uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
BEGIN
  DELETE FROM active_sessions WHERE active_sessions.token = p_token;
  RETURN jsonb_build_object('ok', true);
END; $$;

-- ── platform_admin ──────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION platform_admin(p_token uuid, p_op text, p_args jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess       jsonb;
  _user       jsonb;
  _name       text;
  _ident      text;
  _role_str   text;
  _surname    text;
  _created    jsonb[] := '{}';
  _skipped    jsonb[] := '{}';
  _dup_id     uuid;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;
  IF _sess->>'role' != 'administrator' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Forbidden — only administrators can perform this operation');
  END IF;

  IF p_op = 'addUsers' THEN
    FOR _user IN SELECT * FROM jsonb_array_elements(p_args->'users')
    LOOP
      _name     := _user->>'name';
      _ident    := _user->>'identifier';
      _role_str := COALESCE(_user->>'role', 'user');

      IF _name IS NULL OR _name = '' OR _ident IS NULL OR _ident = '' THEN
        _skipped := array_append(_skipped, jsonb_build_object(
          'name', COALESCE(_name, '(empty)'), 'identifier', COALESCE(_ident, '(empty)'),
          'reason', 'Name and identifier are both required'));
        CONTINUE;
      END IF;

      SELECT id INTO _dup_id FROM profiles WHERE profiles.identifier = _ident;
      IF FOUND THEN
        _skipped := array_append(_skipped, jsonb_build_object(
          'name', _name, 'identifier', _ident,
          'reason', 'Duplicate identifier — user already exists'));
        CONTINUE;
      END IF;

      _surname := lower(split_part(_name, ' ', 1));

      INSERT INTO profiles (role, full_name, identifier, matric_number, password_hash, must_change_password)
      VALUES (_role_str::user_role, _name, _ident, _ident, crypt(_surname, gen_salt('bf')), true);

      _created := array_append(_created, jsonb_build_object(
        'name', _name, 'identifier', _ident, 'default_password', _surname));
    END LOOP;

    RETURN jsonb_build_object('ok', true, 'created', to_jsonb(_created), 'skipped', to_jsonb(_skipped));
  ELSE
    RETURN jsonb_build_object('ok', false, 'error', format('Unknown operation: %s', p_op));
  END IF;
END; $$;

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
