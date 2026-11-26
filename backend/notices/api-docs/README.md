# Local API documentation attribution

Swagger UI 5.34.1 and ReDoc 2.5.4 remain byte-identical to the preceding Vesta
release, including ReDoc's existing local-logo patch. `manifest.json` binds the
shipped assets, original notices and review records. Both backend image classes
install this directory alongside their other license notices under `/usr/share/licenses/`.

Each bundle's `original-notices.json` records every reviewed candidate and its
applicable original files, archive identity, provenance and qualified disposition.
Swagger has 95 source-map candidates plus two independently observed components;
ReDoc has 64 candidates including its independently observed embedded worker.
These are finite conservative inventories, not a claim that source maps prove
which components or exact patch versions were emitted.

The original files preserve upstream bytes. Identical files share a destination,
while their acquisition and component associations remain separate. Roles
distinguish complete grants, inherited copyright notices, author context and
upstream context. ApiDOM source classes and a Redocly license-validation test
are excluded: their names describe code, not legal terms. The Apache selection
for DOMPurify is unchanged; retained alternative/context text does not select it.

`exceptional-originals.json` records the bounded source evidence for packages
whose npm archives omitted a full license. This includes Redocly's original
repository license, XML naming's identical source, and URI replacement's later
owner-merged MIT-0 grant for unchanged code. The URI.js BSD grant remains required
for inherited code. Workerize's original README selects Jason Miller's linked
MIT generator: its untouched template and author notice are supplied together,
without inventing a historical rendered year. Format's author-linked grant has
a current-year header; original package copyrights are preserved alongside it.
Toggle-selection's original upstream grant covers byte-identical source.

`notice-review.json` is the reviewed baseline of required original bytes and
grants per candidate version. It must not be regenerated merely to make a
changed manifest pass. From the repository root, run:

```sh
python3 ci/check_api_doc_attribution.py
pytest backend/tests/test_api_doc_attribution.py backend/tests/test_api_docs_provenance.py
```

The retained-layer scanner invokes the same check and verifies every declared
notice in actual image layers, including removal by later whiteouts. These
checks preserve an established attribution decision; they do not make that
decision. A new bundle, source-map census, archive identity or original notice
requires substantive review and refreshed delivery/source-companion acceptance.
The repository's `docs/developer/dependency-issues-100-104-acceptance.md` records
the original acceptance criteria and exact tested release scope.
