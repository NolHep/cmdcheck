CREATE TABLE IF NOT EXISTS site_settings (
    key         TEXT        PRIMARY KEY,
    value       TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default banner state (disabled)
INSERT INTO site_settings (key, value) VALUES
    ('banner_enabled', 'false'),
    ('banner_message', ''),
    ('banner_type', 'info')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS bug_reports (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    title        TEXT        NOT NULL,
    description  TEXT        NOT NULL,
    severity     TEXT        NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high')),
    contact_email TEXT,
    status       TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'triaging', 'resolved', 'closed')),
    admin_notes  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
