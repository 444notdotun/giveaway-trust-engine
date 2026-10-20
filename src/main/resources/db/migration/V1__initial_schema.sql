-- Slice 1: Migrations and schema (docs/slices/01-migrations-and-schema.md).
-- Every constraint is explicitly named so tests and operators can reference it directly
-- (CLAUDE.md: "Invariants live in database constraints, not only in code").

CREATE TABLE community_manager (
    id          uuid PRIMARY KEY,
    email       text NOT NULL,
    x_handle    text NOT NULL,
    created_at  timestamptz NOT NULL,
    CONSTRAINT uq_community_manager_email UNIQUE (email),
    CONSTRAINT uq_community_manager_x_handle UNIQUE (x_handle)
);

CREATE TABLE account_quota (
    id               uuid PRIMARY KEY,
    cm_id            uuid NOT NULL,
    rolls_allocated  int NOT NULL,
    rolls_used       int NOT NULL,
    CONSTRAINT fk_account_quota_cm_id FOREIGN KEY (cm_id) REFERENCES community_manager (id),
    CONSTRAINT uq_account_quota_cm_id UNIQUE (cm_id),
    CONSTRAINT ck_account_quota_rolls_allocated_nonneg CHECK (rolls_allocated >= 0),
    CONSTRAINT ck_account_quota_rolls_used_nonneg CHECK (rolls_used >= 0),
    CONSTRAINT ck_account_quota_rolls_used_le_allocated CHECK (rolls_used <= rolls_allocated)
);

CREATE TABLE giveaway (
    id                        uuid PRIMARY KEY,
    cm_id                     uuid NOT NULL,
    receipt_slug              text,
    tweet_id                  text NOT NULL,
    chain                     text NOT NULL,
    selection_mode            text NOT NULL,
    target_winners            int NOT NULL,
    status                    text NOT NULL,
    include_retweets          boolean NOT NULL,
    required_follow_handles   text[] NOT NULL DEFAULT '{}',
    excluded_handles          text[] NOT NULL DEFAULT '{}',
    guaranteed_handles        text[] NOT NULL DEFAULT '{}',
    raw_replies_count         int NOT NULL DEFAULT 0,
    valid_entries_count       int NOT NULL DEFAULT 0,
    failure_reason            text,
    failed_stage              text,
    guaranteed_deadline       timestamptz,
    finalized_at              timestamptz,
    created_at                timestamptz NOT NULL,

    CONSTRAINT fk_giveaway_cm_id FOREIGN KEY (cm_id) REFERENCES community_manager (id),
    CONSTRAINT uq_giveaway_receipt_slug UNIQUE (receipt_slug),

    CONSTRAINT ck_giveaway_chain CHECK (chain IN ('EVM', 'SOLANA')),
    CONSTRAINT ck_giveaway_selection_mode CHECK (selection_mode IN ('RANDOM', 'FIRST_N')),
    CONSTRAINT ck_giveaway_target_winners_range CHECK (target_winners BETWEEN 1 AND 100),
    CONSTRAINT ck_giveaway_status CHECK (status IN (
        'PENDING_SCRAPE', 'PROCESSING', 'AWAITING_SHORTFALL_RESOLUTION',
        'AWAITING_GUARANTEED_RESOLUTION', 'FINALIZED', 'FAILED', 'CANCELED'
    )),
    CONSTRAINT ck_giveaway_failure_reason CHECK (failure_reason IS NULL OR failure_reason IN (
        'POST_DELETED', 'ACCOUNT_PRIVATE', 'ACTOR_INPUT_ERROR', 'INGESTION_TIMEOUT', 'UNKNOWN_INGESTION_ERROR'
    )),
    CONSTRAINT ck_giveaway_failed_stage CHECK (failed_stage IS NULL OR failed_stage IN ('REPLIES', 'RETWEETS')),

    -- PRD 3: failure_reason/failed_stage are only ever populated when status = FAILED.
    CONSTRAINT ck_giveaway_failure_fields_only_when_failed CHECK (
        status = 'FAILED' OR (failure_reason IS NULL AND failed_stage IS NULL)
    ),

    -- PRD 10: the receipt slug does not exist before finalization.
    CONSTRAINT ck_giveaway_receipt_slug_only_when_finalized CHECK (
        (receipt_slug IS NOT NULL) = (status = 'FINALIZED')
    ),

    -- status = FINALIZED and finalized_at must agree, in both directions.
    CONSTRAINT ck_giveaway_finalized_at_matches_status CHECK (
        (status = 'FINALIZED') = (finalized_at IS NOT NULL)
    ),

    -- PRD 15: the deadline is stored the moment the giveaway enters this state.
    CONSTRAINT ck_giveaway_guaranteed_deadline_required CHECK (
        status <> 'AWAITING_GUARANTEED_RESOLUTION' OR guaranteed_deadline IS NOT NULL
    ),

    CONSTRAINT ck_giveaway_guaranteed_handles_cardinality CHECK (
        cardinality(guaranteed_handles) <= target_winners
    ),

    -- PRD 17: a handle cannot be both guaranteed a win and excluded.
    CONSTRAINT ck_giveaway_guaranteed_excluded_no_overlap CHECK (
        NOT (guaranteed_handles && excluded_handles)
    ),

    CONSTRAINT ck_giveaway_raw_replies_count_nonneg CHECK (raw_replies_count >= 0),
    CONSTRAINT ck_giveaway_valid_entries_count_nonneg CHECK (valid_entries_count >= 0)
);

CREATE INDEX idx_giveaway_cm_id_status ON giveaway (cm_id, status);

CREATE TABLE giveaway_entry (
    id                      bigserial PRIMARY KEY,
    giveaway_id             uuid NOT NULL,
    author_handle           text NOT NULL,
    raw_text                text NOT NULL,
    extracted_wallet        text,
    reply_timestamp         timestamptz NOT NULL,
    reply_id                bigint NOT NULL,
    is_eligible             boolean NOT NULL DEFAULT true,
    disqualification_code   text,
    is_winner               boolean NOT NULL DEFAULT false,
    winner_allocation       text,

    CONSTRAINT fk_giveaway_entry_giveaway_id FOREIGN KEY (giveaway_id)
        REFERENCES giveaway (id) ON DELETE CASCADE,
    CONSTRAINT uq_giveaway_entry_giveaway_id_reply_id UNIQUE (giveaway_id, reply_id),

    CONSTRAINT ck_giveaway_entry_disqualification_code CHECK (disqualification_code IS NULL OR disqualification_code IN (
        'WRONG_CHAIN', 'DUPLICATE_HANDLE', 'DUPLICATE_WALLET', 'HOST_EXCLUSION',
        'FAILED_REPOST', 'FAILED_FOLLOW_HOST', 'FAILED_FOLLOW_PARTNER'
    )),
    CONSTRAINT ck_giveaway_entry_winner_allocation CHECK (winner_allocation IS NULL OR winner_allocation IN (
        'CM_GUARANTEED', 'RANDOM_SELECTION'
    )),

    -- is_eligible = false exactly when disqualification_code is set; no drift between them.
    CONSTRAINT ck_giveaway_entry_eligibility_matches_code CHECK (
        (NOT is_eligible) = (disqualification_code IS NOT NULL)
    ),

    -- is_winner = true exactly when winner_allocation is set; no drift between them.
    CONSTRAINT ck_giveaway_entry_winner_matches_allocation CHECK (
        is_winner = (winner_allocation IS NOT NULL)
    ),

    CONSTRAINT ck_giveaway_entry_winner_must_be_eligible CHECK (
        NOT (is_winner AND NOT is_eligible)
    )
);

CREATE INDEX idx_entry_giveaway_winner ON giveaway_entry (giveaway_id, is_winner);
CREATE INDEX idx_entry_giveaway_order ON giveaway_entry (giveaway_id, reply_timestamp, reply_id);
CREATE INDEX idx_entry_giveaway_handle ON giveaway_entry (giveaway_id, author_handle);

CREATE TABLE refresh_token (
    token_id    uuid PRIMARY KEY,
    family_id   uuid NOT NULL,
    cm_id       uuid NOT NULL,
    used        boolean NOT NULL DEFAULT false,
    expires_at  timestamptz NOT NULL,
    CONSTRAINT fk_refresh_token_cm_id FOREIGN KEY (cm_id) REFERENCES community_manager (id)
);

CREATE INDEX idx_refresh_token_family_id ON refresh_token (family_id);

CREATE TABLE payment_event (
    id                   uuid PRIMARY KEY,
    provider             text NOT NULL,
    event_id             text NOT NULL,
    cm_id                uuid NOT NULL,
    amount_cents         int NOT NULL,
    rolls_purchased      int NOT NULL,
    status               text NOT NULL,
    provider_reference   text,
    created_at           timestamptz NOT NULL,

    CONSTRAINT fk_payment_event_cm_id FOREIGN KEY (cm_id) REFERENCES community_manager (id),
    CONSTRAINT uq_payment_event_provider_event_id UNIQUE (provider, event_id),
    CONSTRAINT ck_payment_event_amount_cents_nonneg CHECK (amount_cents >= 0),
    CONSTRAINT ck_payment_event_rolls_purchased_positive CHECK (rolls_purchased > 0),
    CONSTRAINT ck_payment_event_status CHECK (status IN ('SUCCEEDED', 'FAILED'))
);

CREATE TABLE giveaway_logs (
    id           bigserial PRIMARY KEY,
    giveaway_id  uuid,
    request_id   text,
    event_type   text NOT NULL,
    detail       jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL
);

CREATE INDEX idx_logs_giveaway_id ON giveaway_logs (giveaway_id);
CREATE INDEX idx_logs_giveaway_id_created_at ON giveaway_logs (giveaway_id, created_at);
