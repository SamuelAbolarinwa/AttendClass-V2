-- =============================================================================
-- 0005: Switch face_enrollments.embedding to pgvector type
-- =============================================================================
-- face-api.js FaceRecognitionNet outputs 128-dimensional float32 descriptors.
-- Using pgvector's vector(128) type enables native cosine similarity search.

SET search_path TO public, extensions;

-- ── 1. Enable pgvector ──────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS vector;

-- ── 2. Convert embedding column from float8[] to vector(128) ────────────────
-- Table is currently empty, so a clean type change is safe.
ALTER TABLE face_enrollments
  ALTER COLUMN embedding TYPE vector(128)
  USING embedding::vector(128);

-- ── 3. IVFFlat index for fast cosine similarity search ──────────────────────
-- lists=10 is appropriate for small-to-medium datasets; increase when the
-- table grows past ~10k rows (rule of thumb: lists ≈ sqrt(row_count)).
CREATE INDEX idx_face_enrollments_embedding
  ON face_enrollments
  USING ivfflat (embedding vector_cosine_ops)
  WITH (lists = 10);
