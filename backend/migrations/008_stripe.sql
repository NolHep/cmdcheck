ALTER TABLE users
  ADD COLUMN IF NOT EXISTS stripe_customer_id       TEXT,
  ADD COLUMN IF NOT EXISTS subscription_status      TEXT NOT NULL DEFAULT 'free',
  ADD COLUMN IF NOT EXISTS subscription_tier        TEXT NOT NULL DEFAULT 'free',
  ADD COLUMN IF NOT EXISTS subscription_updated_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS users_stripe_customer_idx ON users (stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;
