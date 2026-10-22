-- Slice 3: Auth (docs/slices/03-auth.md, Section 0 and Section 2).
-- Append-only: V1__initial_schema.sql is never edited (CLAUDE.md: "Never edit an applied
-- migration"). Precondition (plan doc, Open item 1): both tables are verified empty on staging
-- by Adedotun before this migration is ever applied there -- not re-verified by this migration
-- itself.

-- Section 0: community_manager gains X's own immutable user id, the real upsert key (a CM
-- renaming their X handle must resolve to the same row, not a new one -- x_handle stays
-- mutable and is refreshed on every login, never re-keyed).
ALTER TABLE community_manager ADD COLUMN x_user_id text NOT NULL;
ALTER TABLE community_manager ADD CONSTRAINT uq_community_manager_x_user_id UNIQUE (x_user_id);

-- Section 0: "users.email" is deliberately never requested from X (PRD edit, Section 3), so this
-- flow has no source for community_manager.email at all going forward. Nullability sign-off is
-- still open (plan doc, Open item 5a) but the column must stop being NOT NULL for this slice's
-- login flow to be able to insert a row at all without a fabricated placeholder value (which
-- would collide with the existing UNIQUE constraint on this column).
ALTER TABLE community_manager ALTER COLUMN email DROP NOT NULL;

-- Section 2: refresh_token's secret half is never stored directly -- only its SHA-256 hash.
-- token_id (identifier half, already the primary key from V1) alone is never sufficient to
-- refresh; the secret must also match the stored hash (constant-time comparison, in code).
ALTER TABLE refresh_token ADD COLUMN token_hash bytea NOT NULL;
