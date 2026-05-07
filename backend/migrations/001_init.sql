CREATE TABLE IF NOT EXISTS analyses (
    slug        CHAR(12)    PRIMARY KEY,
    command     TEXT        NOT NULL,
    result      JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS analyses_created_at_idx ON analyses (created_at DESC);
