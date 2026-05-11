-- Trigram index for fast ILIKE search on command text
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_analyses_command_trgm ON analyses USING gin (command gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses (created_at DESC) WHERE deleted_at IS NULL;
