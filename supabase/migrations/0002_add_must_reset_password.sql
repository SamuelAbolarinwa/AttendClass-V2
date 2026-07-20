-- =============================================================================
-- Add must_reset_password flag to profiles
-- =============================================================================
-- Students created by a course rep get a weak default password (their surname).
-- This flag forces them through a password-change screen before they can use
-- any other part of the app.

ALTER TABLE profiles
  ADD COLUMN must_reset_password boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN profiles.must_reset_password
  IS 'True when the account was created with a default password and the user has not yet chosen their own.';
