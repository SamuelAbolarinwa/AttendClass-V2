-- =============================================================================
-- 0013: Proximity Threshold Settings
-- =============================================================================

SET search_path TO public, extensions;

-- ── platform_update_device_settings ──────────────────────────────────────────
-- Allows administrators to update the minimum RSSI signal strength required
-- for a device to accept check-ins.
CREATE OR REPLACE FUNCTION platform_update_device_settings(
  p_token uuid,
  p_device_id text,
  p_rssi_threshold_dbm int
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  _sess jsonb;
BEGIN
  _sess := platform_verify_session(p_token);
  IF NOT (_sess->>'valid')::boolean THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Invalid or expired session');
  END IF;

  IF (_sess->>'role') != 'administrator' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Insufficient permissions');
  END IF;

  UPDATE devices 
  SET rssi_threshold_dbm = p_rssi_threshold_dbm
  WHERE device_id = p_device_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Device not found');
  END IF;

  RETURN jsonb_build_object('ok', true);
END; $$;
