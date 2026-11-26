# Contribute to Vesta Community

Use [GitHub Issues](https://github.com/Insitu-IT/vesta/issues) to report bugs or suggest improvements. The [roadmap](ROADMAP.md) lists areas where you can help. For changes to a public API, the storage lifecycle, authentication or encryption, discuss the intended behavior in an issue first. For a suspected vulnerability, use the [security reporting procedure](SECURITY.md).

Agents working on code or documentation can follow the [contributor reading guide](AGENTS.md). For automation against an existing site, use [Operate Vesta with an automation agent](docs/operating-with-agents.md).

## Prepare a pull request

1. Start a branch from the Community revision you want to change. Keep the full base commit ID.
2. Make one focused change. Describe the outcome, how to reproduce it and the checks you ran. Use synthetic data in examples and remove credentials, VM data and customer identifiers.
3. Open a [pull request](https://github.com/Insitu-IT/vesta/pulls). Reference the issue, credit the authors and identify any adapted material and third-party notices. For an outside contribution, record the acceptance described below.

## Run the development checks

These commands are for contributors working on a source checkout. The [release quickstart](QUICKSTART.md) covers installation from prebuilt assets. The [source map](AGENTS.md) lists entry points for each component.

From the checkout root, use Node.js to build and test the web console:

```sh
cd frontend
npm ci --no-audit
npm run build
node scripts/extract-api-calls.cjs
node --experimental-vm-modules --test tests/*.test.mjs
```

From the checkout root, use Python 3.11 and Node.js for backend unit tests:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r backend/requirements.txt -r tests/requirements-test.txt
node frontend/scripts/extract-api-calls.cjs
python -m pytest backend/tests -q
```

From `agent/`, use the Go toolchain in `go.mod`. For KubeVirt run `make build-kubevirt` and `go test -tags kubevirt ./...`. On a native Linux development host with a C compiler, `pkg-config` and libvirt development headers, run `CGO_ENABLED=1 go test -tags libvirt ./...`. If your change affects a VM provider, describe the test environment and the observed result from a disposable backup and restore.

### Run the local Compose profile

From the checkout root, initialize the local state directory and start the services.

```sh
python3 packaging/community/init-local.py
docker compose --env-file packaging/community/.local/compose.env \
  -f packaging/community/compose.yaml up --build --wait
```

The console listens on `127.0.0.1:8080`. New local databases use `vesta` and the restricted `vesta_runtime` application role. Keep the generated password files and PostgreSQL volume together.

When updating an existing local project from an earlier checkout, run `docker compose down` using that checkout’s Compose file before switching. Keep the same environment file and PostgreSQL volume, omit `--volumes`, and start the updated profile with the command above.

## How a pull request lands

Maintainers review the submitted revision, integrate accepted changes and link the resulting Community commit in the pull request. GitHub may show the PR as closed when its changes land via a separate commit. Contributor attribution follows the change.

## Contribution rights

Read the [Vesta Contribution Terms](CONTRIBUTION-TERMS.md) before submitting. You keep ownership and grant the rights set out in those terms, including their application to Community and commercial distributions. Identify the origin and notices of material you adapted.

After the final push, obtain the full commit ID with `git rev-parse HEAD`. For a
patch file, run `sha256sum change.patch` on the actual file being transferred.
The person submitting the change, or a representative authorized to grant the
rights, records their acceptance for exactly that revision.

For a pull request, post the following as a separate comment from your own
account, replacing `FULL_COMMIT_ID` with the complete ID:

> I accept Vesta Contribution Terms 1.0 (SHA-256 435d4d5e0aa86c21b13ca6fe6c54fd01f4ec105b01a7cac82d113ca154c781ab) for commit FULL_COMMIT_ID. I act for myself.

If you act for an organization, use the final sentence **I act for an
organization I am authorized to represent.** For a patch, replace
`commit FULL_COMMIT_ID` with `patch SHA-256 FULL_PATCH_SHA256`.
Confirm the new revision whenever the submitted material changes.

If you need a confidential exchange, request a **Private follow-up** in [GitHub Issues](https://github.com/Insitu-IT/vesta/issues/new/choose) or ask the maintainer on your PR. Include only the PR or patch reference in that request. Share employer authorizations, contact records and private assent after the maintainer arranges a confidential channel. The person submitting a change, or their authorized representative, supplies the assent for assisted work.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md) in project spaces.
