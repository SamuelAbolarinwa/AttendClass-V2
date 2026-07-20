-- =============================================================================
-- Rename person-role enum values to general-purpose terms
-- =============================================================================
-- student    -> user
-- lecturer   -> manager
-- course_rep -> administrator
--
-- Note: domain objects like courses, enrollments, student_credentials tables
-- are NOT renamed in this migration — only the person-role enum values.

ALTER TYPE user_role RENAME VALUE 'student'    TO 'user';
ALTER TYPE user_role RENAME VALUE 'lecturer'   TO 'manager';
ALTER TYPE user_role RENAME VALUE 'course_rep' TO 'administrator';
