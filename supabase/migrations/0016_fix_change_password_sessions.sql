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
  
  -- Invalidate all other sessions for this account to force re-authentication
  DELETE FROM active_sessions WHERE account_id = _acct.id AND token != p_token;
  
  RETURN jsonb_build_object('ok', true);
END; $$;
