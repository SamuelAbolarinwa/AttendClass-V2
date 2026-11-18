-- =============================================================================
-- 0019 Rollback: Drop Terminal Provisioning RPCs
-- =============================================================================
SET search_path TO public, extensions;

DROP FUNCTION IF EXISTS platform_get_terminal_provisioning(uuid, text);
DROP FUNCTION IF EXISTS platform_trigger_terminal_reprovision(uuid, text);
DROP FUNCTION IF EXISTS platform_update_terminal_key(uuid, text, text);
