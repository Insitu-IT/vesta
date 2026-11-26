# Contribute to Vesta with a coding agent

Start with the [contribution guide](CONTRIBUTING.md). Use a [GitHub issue](https://github.com/Insitu-IT/vesta/issues) or [pull request](https://github.com/Insitu-IT/vesta/pulls) to describe the user-visible outcome, changed files and a check another contributor can repeat.

## What to read first

1. Read the [product overview](README.md) and [first recovery guide](docs/first-recovery.md). These introduce the workloads, backup destination and evidence an operator uses to trust a restore.
2. Follow the [installation quickstart](QUICKSTART.md) for a change to installation, or the [operator API guide](docs/operator-api.md) and [versioned reference](https://vestabackup.com/docs/api/) for an API change. Read the matching test beside the code you plan to change.
3. Use the [roadmap](ROADMAP.md) and the relevant [GitHub issue](https://github.com/Insitu-IT/vesta/issues) to establish the intended outcome. The [contribution guide](CONTRIBUTING.md#run-the-development-checks) lists the supported build profiles and their commands.

If you have been asked to run Vesta at an installation, start with the [agent operating guide](docs/operating-with-agents.md) and [operator CLI](docs/vesta-cli.md).

## Find the implementation

| Area | Start here | Check the change |
|---|---|---|
| API and control plane | `backend/app.py`, `backend/routers/`, `backend/core/` | Run the affected `backend/tests/` module. Use disposable PostgreSQL for role, isolation and concurrency checks. |
| Web console | `frontend/src/main.js`, `frontend/src/pages/` | Run the frontend build and affected Node tests. Update English and Hebrew resources for user-visible changes. |
| Workload agents | `agent/cmd/`, `agent/internal/backup/`, `agent/internal/restore/` | Use the matching libvirt or KubeVirt build tag and host prerequisites in the contribution guide. |
| Offline restore | `agent/cmd/`, `agent/internal/storagerestore/` | From `agent/`, run `go test ./internal/storagerestore ./cmd/...`. |
| Installation and manuals | `packaging/okd/`, `packaging/community/`, `docs/` | Follow the links from the README and the extracted kit. Name the profile you exercised. |

## Check the behavior you changed

Use a disposable installation and synthetic fixtures. Keep actual credentials, customer inventory and guest data out of tests, commits and issue reports. For changes to authentication or tenant isolation, exercise both an allowed and a denied request. For storage or recovery changes, preserve existing backup chains and compare a fresh restore with known guest data. For an API change, check the runtime response and the matching API description.

Preserve existing installation identities, stored formats and rollback paths when changing configuration or packaging. Keep backups and restores available across license checks. Explain any compatibility change in the pull request and link the updated operator instructions. Use the official [GitHub releases](https://github.com/Insitu-IT/vesta/releases) for customer installation directions.

## Hand off the contribution

For an outside submission, give the submitting person the exact final commit ID or patch digest, test results, and any third-party origins and notices. Follow the [contribution rights instructions](CONTRIBUTING.md#contribution-rights). The person or their authorized representative reads the [terms](CONTRIBUTION-TERMS.md) and records their own assent. Give them the new revision if the patch changes.
