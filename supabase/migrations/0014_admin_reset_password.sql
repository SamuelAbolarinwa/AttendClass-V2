-- =============================================================================
-- 0014: Add resetPassword operation to platform_admin
-- =============================================================================
SET search_path TO public, extensions;

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
  
  -- for resetPassword
  _target_acct_id uuid;
  _target_acct    profiles%ROWTYPE;
  _default_pwd    text;
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
  
  ELSIF p_op = 'resetPassword' THEN
    _target_acct_id := (p_args->>'account_id')::uuid;
    SELECT * INTO _target_acct FROM profiles WHERE id = _target_acct_id;
    IF _target_acct IS NULL THEN
      RETURN jsonb_build_object('ok', false, 'error', 'Account not found');
    END IF;

    _default_pwd := lower(split_part(_target_acct.full_name, ' ', 1));

    UPDATE profiles
    SET password_hash = crypt(_default_pwd, gen_salt('bf')),
        must_change_password = true
    WHERE id = _target_acct_id;

    DELETE FROM active_sessions WHERE account_id = _target_acct_id;

    RETURN jsonb_build_object('ok', true, 'new_default_password', _default_pwd);

  ELSE
    RETURN jsonb_build_object('ok', false, 'error', format('Unknown operation: %s', p_op));
  END IF;
END; $$;
