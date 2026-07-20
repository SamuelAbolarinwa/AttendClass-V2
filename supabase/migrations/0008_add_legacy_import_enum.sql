-- =============================================================================
-- 0008: Add legacy_import to attendance_method enum
-- =============================================================================

ALTER TYPE attendance_method ADD VALUE IF NOT EXISTS 'legacy_import';
