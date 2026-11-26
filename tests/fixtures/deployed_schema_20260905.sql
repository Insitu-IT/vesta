--
-- PostgreSQL database dump
--

\restrict Nw9ALHLI0xCQIwW4er6aM1yGcbQd7ic7BBCctbka8Anxb4VsfvIsp4K3wYXM97N

-- Dumped from database version 15.19
-- Dumped by pg_dump version 15.19

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activity_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activity_logs (
    id character varying NOT NULL,
    user_id character varying NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(50),
    resource_id character varying,
    details jsonb,
    created_at timestamp without time zone
);


--
-- Name: agent_api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_api_keys (
    id character varying NOT NULL,
    agent_id character varying NOT NULL,
    name character varying(255),
    key_hash character varying(64) NOT NULL,
    key_prefix character varying(16) NOT NULL,
    expires_at timestamp without time zone,
    enabled boolean,
    last_used_at timestamp without time zone,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: agent_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_certificates (
    id character varying NOT NULL,
    agent_id character varying NOT NULL,
    serial_number character varying(64),
    fingerprint character varying(64) NOT NULL,
    common_name character varying(255),
    issued_at timestamp without time zone DEFAULT now(),
    expires_at timestamp without time zone NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying,
    revoked_at timestamp without time zone
);


--
-- Name: agent_registration_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_registration_keys (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    key_hash character varying(64) NOT NULL,
    key_prefix character varying(16) NOT NULL,
    expires_at timestamp without time zone,
    enabled boolean,
    max_uses integer,
    use_count integer,
    last_used_at timestamp without time zone,
    created_by character varying NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
    id character varying NOT NULL,
    hostname character varying(255) NOT NULL,
    display_name character varying(255),
    status character varying(20),
    last_heartbeat timestamp without time zone,
    created_at timestamp without time zone,
    api_key_hash character varying(64),
    key_created_at timestamp without time zone,
    key_last_used_at timestamp without time zone,
    capabilities jsonb,
    metrics jsonb,
    ip_address character varying(45),
    port integer,
    version character varying(32),
    platform character varying(64),
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    cert_fingerprint character varying(64),
    cert_expires_at timestamp without time zone,
    mtls_enabled boolean DEFAULT false
);


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: backup_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.backup_queue (
    id character varying NOT NULL,
    vm_id character varying NOT NULL,
    priority integer,
    retention_days integer,
    backup_type character varying(20),
    tags jsonb,
    exclude_disks jsonb,
    workers integer,
    status character varying(20),
    "position" integer,
    queued_at timestamp without time zone,
    started_at timestamp without time zone,
    created_by character varying,
    schedule_id character varying,
    is_bulk_operation boolean
);


--
-- Name: backup_verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.backup_verifications (
    id character varying NOT NULL,
    backup_id character varying NOT NULL,
    status character varying(20),
    verification_type character varying(50),
    result_message text,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_by character varying,
    created_at timestamp without time zone
);


--
-- Name: backups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.backups (
    id character varying NOT NULL,
    vm_id character varying NOT NULL,
    status character varying(20),
    progress integer,
    size_bytes bigint,
    retention_days integer,
    tags jsonb,
    created_at timestamp without time zone,
    completed_at timestamp without time zone,
    backup_type character varying(20) DEFAULT 'full'::character varying,
    storage_path character varying(512),
    exclude_disks jsonb DEFAULT '[]'::jsonb,
    workers integer,
    checkpoints jsonb DEFAULT '[]'::jsonb,
    encryption_key_id character varying,
    wrapped_dek text,
    chain_id character varying,
    parent_backup_id character varying,
    chain_position integer
);


--
-- Name: demo_rate_buckets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.demo_rate_buckets (
    key_hash character varying(64) NOT NULL,
    window_started_at timestamp without time zone NOT NULL,
    request_count integer NOT NULL
);


--
-- Name: demo_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.demo_sessions (
    id character varying NOT NULL,
    token_hash character varying(64) NOT NULL,
    fixture_version character varying(32) NOT NULL,
    state jsonb NOT NULL,
    created_at timestamp without time zone NOT NULL,
    last_seen_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    absolute_expires_at timestamp without time zone NOT NULL
);


--
-- Name: encryption_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.encryption_keys (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    algorithm character varying(50) DEFAULT 'aes-256-gcm'::character varying,
    key_hash character varying(64) NOT NULL,
    encrypted_material text,
    status character varying(20) DEFAULT 'active'::character varying,
    provider character varying(50) DEFAULT 'local'::character varying,
    provider_key_ref character varying(255),
    created_at timestamp without time zone DEFAULT now(),
    created_by character varying,
    rotated_at timestamp without time zone,
    replaced_by_id character varying,
    backed_up boolean DEFAULT false,
    backed_up_at timestamp without time zone,
    backed_up_locations jsonb DEFAULT '[]'::jsonb
);


--
-- Name: notification_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_logs (
    id character varying NOT NULL,
    rule_id character varying,
    event_type character varying(50) NOT NULL,
    recipient character varying(255) NOT NULL,
    subject character varying(500),
    body text,
    status character varying(20),
    error_message text,
    sent_at timestamp without time zone,
    read boolean DEFAULT false NOT NULL
);


--
-- Name: notification_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_rules (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    event_type character varying(50) NOT NULL,
    enabled boolean,
    notification_type character varying(20),
    recipients jsonb,
    conditions jsonb,
    created_by character varying NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    template text
);


--
-- Name: orchestrator_api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orchestrator_api_keys (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    key_hash character varying(64) NOT NULL,
    key_prefix character varying(16) NOT NULL,
    expires_at timestamp without time zone,
    enabled boolean,
    last_used_at timestamp without time zone,
    created_by character varying NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    parent_id character varying,
    settings jsonb,
    branding jsonb,
    limits jsonb,
    enabled boolean,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: report_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.report_executions (
    id character varying NOT NULL,
    report_id character varying,
    status character varying(20),
    file_path character varying(500),
    file_size_bytes integer,
    error_message text,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone,
    file_content bytea,
    file_name character varying(255),
    content_type character varying(100)
);


--
-- Name: reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reports (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    report_type character varying(50) NOT NULL,
    schedule character varying(50),
    enabled boolean,
    format character varying(20),
    recipients jsonb,
    filters jsonb,
    last_run_at timestamp without time zone,
    next_run_at timestamp without time zone,
    created_by character varying NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: restores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.restores (
    id character varying NOT NULL,
    backup_id character varying NOT NULL,
    target_vm_id character varying,
    restore_to_original boolean,
    target_vm_name character varying(255),
    status character varying(20),
    progress integer,
    error_message text,
    created_by character varying NOT NULL,
    created_at timestamp without time zone,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    until_checkpoint character varying(255),
    auto_define boolean DEFAULT false,
    adjust_config boolean DEFAULT false,
    selected_disks jsonb DEFAULT '[]'::jsonb
);


--
-- Name: saved_searches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saved_searches (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    search_type character varying(20) NOT NULL,
    filters jsonb,
    created_by character varying NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    is_public boolean DEFAULT false NOT NULL
);


--
-- Name: schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schedules (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    vm_id character varying,
    vm_group_id character varying,
    cron_expression character varying(100) NOT NULL,
    retention_days integer,
    tags jsonb,
    enabled boolean,
    last_run_at timestamp without time zone,
    next_run_at timestamp without time zone,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    exclude_disks jsonb DEFAULT '[]'::jsonb,
    workers integer,
    backup_type character varying(20) DEFAULT 'full'::character varying
);


--
-- Name: secrets_v3; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secrets_v3 (
    key character varying(100) NOT NULL,
    encrypted_value text,
    source character varying(20) DEFAULT 'ui'::character varying,
    vault_path character varying(255),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: settings_v3; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.settings_v3 (
    key character varying(100) NOT NULL,
    value text,
    value_type character varying(20) DEFAULT 'string'::character varying,
    source character varying(20) DEFAULT 'default'::character varying,
    updated_at timestamp without time zone DEFAULT now(),
    updated_by character varying(100)
);


--
-- Name: system_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_events (
    id character varying NOT NULL,
    event_type character varying(100) NOT NULL,
    source character varying(50) NOT NULL,
    source_id character varying,
    resource_type character varying(50),
    resource_id character varying,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: system_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_settings (
    id character varying NOT NULL,
    category character varying(50) NOT NULL,
    key character varying(100) NOT NULL,
    value text,
    value_type character varying(20),
    description text,
    updated_at timestamp without time zone,
    updated_by character varying
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id character varying NOT NULL,
    username character varying(100) NOT NULL,
    password_hash character varying(255) NOT NULL,
    role character varying(20) NOT NULL,
    created_at timestamp without time zone,
    email character varying(255),
    full_name character varying(255),
    last_login timestamp without time zone,
    auth_source character varying(20) DEFAULT 'local'::character varying,
    role_source character varying(20) DEFAULT 'local'::character varying,
    oidc_subject character varying(255),
    oidc_issuer character varying(255),
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: vm_group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vm_group_members (
    vm_id character varying NOT NULL,
    group_id character varying NOT NULL,
    added_at timestamp without time zone
);


--
-- Name: vm_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vm_groups (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    created_at timestamp without time zone,
    tags json,
    group_type character varying(20) DEFAULT 'static'::character varying NOT NULL,
    rules jsonb,
    rules_match character varying(10) DEFAULT 'all'::character varying NOT NULL
);


--
-- Name: vms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vms (
    id character varying NOT NULL,
    name character varying(255) NOT NULL,
    agent_id character varying NOT NULL,
    state character varying(20),
    created_at timestamp without time zone,
    uuid character varying(36),
    memory_kb bigint,
    vcpu_count integer,
    disks jsonb DEFAULT '[]'::jsonb,
    vm_metadata jsonb DEFAULT '{}'::jsonb
);


--
-- Name: activity_logs activity_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activity_logs
    ADD CONSTRAINT activity_logs_pkey PRIMARY KEY (id);


--
-- Name: agent_api_keys agent_api_keys_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys
    ADD CONSTRAINT agent_api_keys_agent_id_key UNIQUE (agent_id);


--
-- Name: agent_api_keys agent_api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys
    ADD CONSTRAINT agent_api_keys_pkey PRIMARY KEY (id);


--
-- Name: agent_certificates agent_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_certificates
    ADD CONSTRAINT agent_certificates_pkey PRIMARY KEY (id);


--
-- Name: agent_registration_keys agent_registration_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_registration_keys
    ADD CONSTRAINT agent_registration_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: agent_registration_keys agent_registration_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_registration_keys
    ADD CONSTRAINT agent_registration_keys_pkey PRIMARY KEY (id);


--
-- Name: agents agents_hostname_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_hostname_key UNIQUE (hostname);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);


--
-- Name: alembic_version alembic_version_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkey PRIMARY KEY (version_num);


--
-- Name: backup_queue backup_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_queue
    ADD CONSTRAINT backup_queue_pkey PRIMARY KEY (id);


--
-- Name: backup_verifications backup_verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_verifications
    ADD CONSTRAINT backup_verifications_pkey PRIMARY KEY (id);


--
-- Name: backups backups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backups
    ADD CONSTRAINT backups_pkey PRIMARY KEY (id);


--
-- Name: demo_rate_buckets demo_rate_buckets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.demo_rate_buckets
    ADD CONSTRAINT demo_rate_buckets_pkey PRIMARY KEY (key_hash);


--
-- Name: demo_sessions demo_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.demo_sessions
    ADD CONSTRAINT demo_sessions_pkey PRIMARY KEY (id);


--
-- Name: demo_sessions demo_sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.demo_sessions
    ADD CONSTRAINT demo_sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: encryption_keys encryption_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.encryption_keys
    ADD CONSTRAINT encryption_keys_pkey PRIMARY KEY (id);


--
-- Name: notification_logs notification_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_logs
    ADD CONSTRAINT notification_logs_pkey PRIMARY KEY (id);


--
-- Name: notification_rules notification_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_rules
    ADD CONSTRAINT notification_rules_pkey PRIMARY KEY (id);


--
-- Name: orchestrator_api_keys orchestrator_api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orchestrator_api_keys
    ADD CONSTRAINT orchestrator_api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: orchestrator_api_keys orchestrator_api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orchestrator_api_keys
    ADD CONSTRAINT orchestrator_api_keys_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: report_executions report_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_executions
    ADD CONSTRAINT report_executions_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: restores restores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.restores
    ADD CONSTRAINT restores_pkey PRIMARY KEY (id);


--
-- Name: saved_searches saved_searches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saved_searches
    ADD CONSTRAINT saved_searches_pkey PRIMARY KEY (id);


--
-- Name: schedules schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules
    ADD CONSTRAINT schedules_pkey PRIMARY KEY (id);


--
-- Name: secrets_v3 secrets_v3_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets_v3
    ADD CONSTRAINT secrets_v3_pkey PRIMARY KEY (key);


--
-- Name: settings_v3 settings_v3_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings_v3
    ADD CONSTRAINT settings_v3_pkey PRIMARY KEY (key);


--
-- Name: system_events system_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_events
    ADD CONSTRAINT system_events_pkey PRIMARY KEY (id);


--
-- Name: system_settings system_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: vm_group_members vm_group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_group_members
    ADD CONSTRAINT vm_group_members_pkey PRIMARY KEY (vm_id, group_id);


--
-- Name: vm_groups vm_groups_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_groups
    ADD CONSTRAINT vm_groups_name_key UNIQUE (name);


--
-- Name: vm_groups vm_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_groups
    ADD CONSTRAINT vm_groups_pkey PRIMARY KEY (id);


--
-- Name: vms vms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vms
    ADD CONSTRAINT vms_pkey PRIMARY KEY (id);


--
-- Name: ix_agent_certificates_serial_number; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_agent_certificates_serial_number ON public.agent_certificates USING btree (serial_number);


--
-- Name: ix_backup_queue_status_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_backup_queue_status_priority ON public.backup_queue USING btree (status, priority);


--
-- Name: ix_backups_chain_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_backups_chain_id ON public.backups USING btree (chain_id);


--
-- Name: ix_demo_sessions_absolute_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_demo_sessions_absolute_expires_at ON public.demo_sessions USING btree (absolute_expires_at);


--
-- Name: ix_demo_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_demo_sessions_expires_at ON public.demo_sessions USING btree (expires_at);


--
-- Name: ix_demo_sessions_token_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_demo_sessions_token_hash ON public.demo_sessions USING btree (token_hash);


--
-- Name: ix_encryption_keys_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_encryption_keys_status ON public.encryption_keys USING btree (status);


--
-- Name: ix_system_events_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_system_events_created_at ON public.system_events USING btree (created_at);


--
-- Name: ix_system_events_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_system_events_event_type ON public.system_events USING btree (event_type);


--
-- Name: ix_users_oidc_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_oidc_subject ON public.users USING btree (oidc_subject, oidc_issuer) WHERE (oidc_subject IS NOT NULL);


--
-- Name: ix_users_username; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_users_username ON public.users USING btree (username);


--
-- Name: activity_logs activity_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activity_logs
    ADD CONSTRAINT activity_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: agent_api_keys agent_api_keys_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_api_keys
    ADD CONSTRAINT agent_api_keys_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: agent_certificates agent_certificates_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_certificates
    ADD CONSTRAINT agent_certificates_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- Name: agent_registration_keys agent_registration_keys_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_registration_keys
    ADD CONSTRAINT agent_registration_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: backup_queue backup_queue_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_queue
    ADD CONSTRAINT backup_queue_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: backup_queue backup_queue_schedule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_queue
    ADD CONSTRAINT backup_queue_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES public.schedules(id);


--
-- Name: backup_queue backup_queue_vm_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_queue
    ADD CONSTRAINT backup_queue_vm_id_fkey FOREIGN KEY (vm_id) REFERENCES public.vms(id);


--
-- Name: backup_verifications backup_verifications_backup_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_verifications
    ADD CONSTRAINT backup_verifications_backup_id_fkey FOREIGN KEY (backup_id) REFERENCES public.backups(id);


--
-- Name: backup_verifications backup_verifications_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backup_verifications
    ADD CONSTRAINT backup_verifications_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: backups backups_chain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backups
    ADD CONSTRAINT backups_chain_id_fkey FOREIGN KEY (chain_id) REFERENCES public.backups(id);


--
-- Name: backups backups_encryption_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backups
    ADD CONSTRAINT backups_encryption_key_id_fkey FOREIGN KEY (encryption_key_id) REFERENCES public.encryption_keys(id);


--
-- Name: backups backups_parent_backup_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backups
    ADD CONSTRAINT backups_parent_backup_id_fkey FOREIGN KEY (parent_backup_id) REFERENCES public.backups(id);


--
-- Name: backups backups_vm_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.backups
    ADD CONSTRAINT backups_vm_id_fkey FOREIGN KEY (vm_id) REFERENCES public.vms(id);


--
-- Name: encryption_keys encryption_keys_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.encryption_keys
    ADD CONSTRAINT encryption_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: encryption_keys encryption_keys_replaced_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.encryption_keys
    ADD CONSTRAINT encryption_keys_replaced_by_id_fkey FOREIGN KEY (replaced_by_id) REFERENCES public.encryption_keys(id);


--
-- Name: notification_logs notification_logs_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_logs
    ADD CONSTRAINT notification_logs_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.notification_rules(id);


--
-- Name: notification_rules notification_rules_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_rules
    ADD CONSTRAINT notification_rules_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: orchestrator_api_keys orchestrator_api_keys_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orchestrator_api_keys
    ADD CONSTRAINT orchestrator_api_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: organizations organizations_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.organizations(id);


--
-- Name: report_executions report_executions_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_executions
    ADD CONSTRAINT report_executions_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.reports(id);


--
-- Name: reports reports_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: restores restores_backup_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.restores
    ADD CONSTRAINT restores_backup_id_fkey FOREIGN KEY (backup_id) REFERENCES public.backups(id);


--
-- Name: restores restores_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.restores
    ADD CONSTRAINT restores_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: restores restores_target_vm_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.restores
    ADD CONSTRAINT restores_target_vm_id_fkey FOREIGN KEY (target_vm_id) REFERENCES public.vms(id);


--
-- Name: saved_searches saved_searches_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saved_searches
    ADD CONSTRAINT saved_searches_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: schedules schedules_vm_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules
    ADD CONSTRAINT schedules_vm_group_id_fkey FOREIGN KEY (vm_group_id) REFERENCES public.vm_groups(id);


--
-- Name: schedules schedules_vm_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules
    ADD CONSTRAINT schedules_vm_id_fkey FOREIGN KEY (vm_id) REFERENCES public.vms(id);


--
-- Name: system_settings system_settings_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id);


--
-- Name: vm_group_members vm_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_group_members
    ADD CONSTRAINT vm_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.vm_groups(id);


--
-- Name: vm_group_members vm_group_members_vm_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vm_group_members
    ADD CONSTRAINT vm_group_members_vm_id_fkey FOREIGN KEY (vm_id) REFERENCES public.vms(id);


--
-- Name: vms vms_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vms
    ADD CONSTRAINT vms_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);


--
-- PostgreSQL database dump complete
--

\unrestrict Nw9ALHLI0xCQIwW4er6aM1yGcbQd7ic7BBCctbka8Anxb4VsfvIsp4K3wYXM97N

