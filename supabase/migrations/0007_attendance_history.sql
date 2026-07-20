-- =============================================================================
-- 0007: Attendance History & Cancelled Days
-- =============================================================================

-- ── 1. Create cancelled_days table ──────────────────────────────────────────
CREATE TABLE cancelled_days (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  cancelled_date  date        NOT NULL UNIQUE,
  reason          text,
  created_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE  cancelled_days                IS 'Records days where attendance was cancelled (e.g. holidays) so they do not count against the student.';
COMMENT ON COLUMN cancelled_days.cancelled_date IS 'The specific date that was cancelled.';
COMMENT ON COLUMN cancelled_days.reason         IS 'Optional reason for cancellation (e.g. "Public Holiday").';

ALTER TABLE cancelled_days ENABLE ROW LEVEL SECURITY;
CREATE POLICY cancelled_days_permissive ON cancelled_days FOR ALL USING (true) WITH CHECK (true);

-- ── 2. Add tracking_start_date to profiles ──────────────────────────────────
ALTER TABLE profiles 
  ADD COLUMN tracking_start_date date;

COMMENT ON COLUMN profiles.tracking_start_date IS 'The date from which this account''s attendance percentage is calculated. If NULL, use created_at.';

-- ── 3. Add Index ────────────────────────────────────────────────────────────
CREATE INDEX idx_cancelled_days_date ON cancelled_days (cancelled_date);

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
