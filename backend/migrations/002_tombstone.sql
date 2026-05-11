-- Add soft-delete support. A deleted analysis becomes a tombstone:
-- the slug stays valid and returns a "deleted" indicator instead of 404.
-- Per spec: "show 'this command was deleted' so old links don't break confusingly."
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
