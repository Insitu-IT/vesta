# Staged agent API-key rotation

On the installed API, open `/docs` or `/redoc` for your version and authentication profile. Keep your agent ID and a private location for the one-time key response ready.

`POST /api/v1/agents/{agent_id}/rotate-key` stages a candidate. It does not invalidate the current key. Supply a fresh UUID
in `Idempotency-Key`, save the
one-time response to a private file, and retain the returned `rotation_id` and
`request_id`. Reusing the same identity returns the original metadata without
`api_key`; the key is not recoverable from the server. A different rotation while
one remains pending returns 409. The default candidate lifetime is 24 hours;
`site.json` accepts `agent_key_rotation_ttl_hours` from 1 through 168; follow
the ordinary reconfiguration procedure to change it. The installer projects it
to `AGENT_KEY_ROTATION_TTL_HOURS`. Existing candidates retain their original
expiry; this setting affects future candidates only.

Before rotating through automation, require `agent_key_rotation:
staged-candidate-activation` from `GET /api/v1/operator/capabilities`. Clients
written for immediate rotation must use the activation step below before
restarting an agent with the returned key.

1. Save the first response directly to a file owned by the current user, mode
   0600 or stricter. Do not paste the key into shell arguments or diagnostic logs.
2. Install the saved candidate into the agent's managed `AGENT_API_KEY`
   configuration using the installation's normal secret-management procedure.
   Keep the previous configuration available until activation is reconciled.
   Keep the running agent on its old key; do not reload or restart it yet.
3. Deliberately prove possession of that saved candidate:

   ```sh
   python3 scripts/activate-agent-key.py --activate \
     --api-url https://vesta-api.example.test \
     --agent-id AGENT_UUID --rotation-id ROTATION_UUID \
     --candidate-file /private/saved-rotation.json --ca-file /private/ca.pem
   ```

   The repository [activation helper](../../scripts/activate-agent-key.py) is
   shipped as `install/activate-agent-key.py` in an extracted offline kit. Use
   that path instead of `scripts/activate-agent-key.py` when working from the kit.

   `--client-cert` and `--client-key` are required together when mTLS is required.
   They must represent the same agent. The helper verifies server TLS, refuses
   redirects and reads only a regular private candidate file. It accepts either
   the original JSON response or a file containing only the key. It prints only
   the known agent/rotation IDs and activated state.
4. Reload or restart the agent through the installation's normal procedure so
   its running process uses the installed candidate. Verify a fresh authenticated
   heartbeat. Configuration-file persistence, candidate possession and a running
   agent's configuration are separate observations; the helper does not claim
   to verify agent installation or manage a service restart.

Activation atomically makes the candidate current and invalidates the predecessor.
Old-key requests remain valid before activation. A candidate cannot authenticate
ordinary agent requests before activation. The limited activation route is
`POST /api/v1/agents/{agent_id}/key-rotations/{rotation_id}/activate` with the
candidate in `X-Agent-Key`, plus verified mTLS when configured. A user Bearer
session is not candidate proof. The original issuing administrator must still
exist, be active, remain an administrator, and belong to an enabled organization.

If activation's response is lost, repeat the helper for the **same** saved
candidate and rotation. That proof returns activated metadata without another
swap while the credential remains current. Never create another rotation merely
because an HTTP response or local file write failed. A lost first delivery can
be reconciled with the request receipt and the admin status endpoint; deliberately
cancel the pending candidate before creating a replacement under a new identity.

Administrators can inspect `GET /api/v1/agents/{agent_id}/key-rotations` and
`GET /api/v1/agents/{agent_id}/key-rotations/{rotation_id}`. These return metadata
only. `DELETE /api/v1/agents/{agent_id}/key-rotations/{rotation_id}` cancels a
pending candidate while retaining the current credential; repeated cancellation
is harmless. Activated candidates cannot be cancelled. Expired candidates cannot
activate. Status reads report logical expiry without writing; expiry is persisted
when an expired candidate is activated, cancelled or superseded by a deliberate
new staging request. No expiry or cancellation automatically rotates, replaces or
revokes the current key.

Existing agents without an `AgentAPIKey` metadata row retain legacy key support.
When a row exists, its hash must agree with the current agent hash and it must be
enabled and unexpired. This is checked both on ordinary agent authentication and
on storage callback proof revalidation. A rotation does not broaden original
backup-attempt or export-custody authority.
