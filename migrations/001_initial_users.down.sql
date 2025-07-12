-- Rollback: Initial user table
-- Created at: 2025-01-12

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP INDEX IF EXISTS idx_users_created_at;
DROP INDEX IF EXISTS idx_users_email;

DROP TABLE IF EXISTS users;
