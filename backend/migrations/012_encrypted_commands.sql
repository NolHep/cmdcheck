-- Track whether a stored command is Fernet-encrypted.
-- false = plaintext (public analyses and legacy rows)
-- true  = encrypted with ENCRYPTION_KEY (private analyses)
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS encrypted BOOLEAN NOT NULL DEFAULT false;
