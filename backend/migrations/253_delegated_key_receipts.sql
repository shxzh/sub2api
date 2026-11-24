-- Retain the receipt after revocation so a delayed issue retry cannot create another key.
CREATE TABLE IF NOT EXISTS delegated_key_receipts (
    operation char(64) PRIMARY KEY,
    key_id bigint
);
