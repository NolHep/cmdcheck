ALTER TABLE analyses
  ADD COLUMN IF NOT EXISTS is_private BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS user_id    UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS analyses_user_id_idx  ON analyses (user_id)    WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS analyses_public_idx   ON analyses (created_at) WHERE is_private = false AND deleted_at IS NULL;
