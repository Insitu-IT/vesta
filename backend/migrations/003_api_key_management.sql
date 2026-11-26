-- Migration 003: API Key Management System
-- Adds tables for managing orchestrator, registration, and agent API keys

-- Create OrchestratorAPIKey table
CREATE TABLE IF NOT EXISTS orchestrator_api_keys (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,
    expires_at TIMESTAMP NULL,
    enabled BOOLEAN DEFAULT TRUE NOT NULL,
    last_used_at TIMESTAMP NULL,
    created_by VARCHAR(36) NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX idx_orchestrator_keys_key_hash ON orchestrator_api_keys(key_hash);
CREATE INDEX idx_orchestrator_keys_enabled ON orchestrator_api_keys(enabled);
CREATE INDEX idx_orchestrator_keys_created_by ON orchestrator_api_keys(created_by);

-- Create AgentRegistrationKey table
CREATE TABLE IF NOT EXISTS agent_registration_keys (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,
    expires_at TIMESTAMP NULL,
    enabled BOOLEAN DEFAULT TRUE NOT NULL,
    max_uses INTEGER NULL,
    use_count INTEGER DEFAULT 0 NOT NULL,
    last_used_at TIMESTAMP NULL,
    created_by VARCHAR(36) NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX idx_registration_keys_key_hash ON agent_registration_keys(key_hash);
CREATE INDEX idx_registration_keys_enabled ON agent_registration_keys(enabled);
CREATE INDEX idx_registration_keys_created_by ON agent_registration_keys(created_by);

-- Create AgentAPIKey table
CREATE TABLE IF NOT EXISTS agent_api_keys (
    id VARCHAR(36) PRIMARY KEY,
    agent_id VARCHAR(36) NOT NULL UNIQUE REFERENCES agents(id) ON DELETE CASCADE,
    name VARCHAR(255) NULL,
    key_hash VARCHAR(64) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    expires_at TIMESTAMP NULL,
    enabled BOOLEAN DEFAULT TRUE NOT NULL,
    last_used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX idx_agent_api_keys_agent_id ON agent_api_keys(agent_id);
CREATE INDEX idx_agent_api_keys_key_hash ON agent_api_keys(key_hash);
CREATE INDEX idx_agent_api_keys_enabled ON agent_api_keys(enabled);

-- Add display_name column to agents table
ALTER TABLE agents ADD COLUMN IF NOT EXISTS display_name VARCHAR(255) NULL;

-- Add comment explaining display_name
COMMENT ON COLUMN agents.display_name IS 'UI-configurable name that overrides hostname for display purposes';

-- Migrate existing agents to AgentAPIKey table
-- This creates AgentAPIKey records for any agents that have an api_key_hash
INSERT INTO agent_api_keys (id, agent_id, name, key_hash, key_prefix, enabled, created_at, updated_at)
SELECT
    gen_random_uuid()::text AS id,
    a.id AS agent_id,
    a.hostname AS name,
    a.api_key_hash AS key_hash,
    LEFT(a.api_key_hash, 8) AS key_prefix,
    TRUE AS enabled,
    a.key_created_at AS created_at,
    CURRENT_TIMESTAMP AS updated_at
FROM agents a
WHERE a.api_key_hash IS NOT NULL
ON CONFLICT (agent_id) DO NOTHING;
