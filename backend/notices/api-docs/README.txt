Offline API documentation browser dependencies

Swagger UI 5.34.1 (Apache-2.0)
  https://github.com/swagger-api/swagger-ui/tree/v5.34.1
ReDoc 2.5.4 (MIT)
  https://github.com/Redocly/redoc/tree/v2.5.4

The pinned npm distribution files are copied with one documented exception:
ReDoc hard-codes https://cdn.redoc.ly/redoc/logo-mini.svg. That single URL is
replaced with ./docs-assets/redocly-logo.svg, an unmodified local copy of the same
upstream attribution logo. No attribution or branding is removed. manifest.json
records the original ReDoc JS hash and the exact replacement, alongside the
shipped JS hash. All other distribution bytes remain unmodified. manifest.json
records pinned archive URLs, registry SHA-512 integrity values (verified before
extraction), and SHA-256 hashes of shipped files and upstream license notices.
Each package directory preserves its upstream license and bundled dependency
notices; Swagger also supplies NOTICE. No source maps or build tooling ship.
The favicon matches branding/vesta/packs/vesta-1.2.0/summer-light.svg,
owned by S2 Tikshuv LTD.

FastAPI integration: https://fastapi.tiangolo.com/how-to/custom-docs-ui-assets/
Swagger validator: https://swagger.io/docs/open-source-tools/swagger-ui/usage/configuration/
ReDoc options: https://redocly.com/docs/redoc/v2.x/config

Runtime policy: all resources are served from the API origin. ReDoc Google Font
links are disabled; typography uses system fonts. ReDoc 2 has no telemetry
exporter; Swagger's online validator is explicitly disabled. ReDoc's search uses
the bundled local blob worker; only /redoc receives worker-src 'self' blob:.
Other documents keep their existing CSP. OAuth redirects
use FastAPI's bundled redirect page and retain the configured initialization.

Updating: download an exact version's registry metadata and archive, verify the
archive's integrity, copy only runtime JS/CSS and all applicable bundled notices,
and refresh manifest.json. Keep this inventory in both backend images. Run the
focused docs tests, built-image hash verification and real browser acceptance
with off-origin requests blocked before releasing an update.

Embedded component supplement
The components.json files retain an unqualified census of source-map paths from
the same npm archives, with candidate publisher-lock nodes and original source
comparisons. These are not accepted emitted-component inventories. Coordinate
checks use JavaScript line terminators and UTF-16 columns: both original maps
are in bounds, which is necessary but does not prove correspondence. In
particular the actual Swagger bundle contains a neotraverse diagnostic whereas
its map lacks that path and lists traverse/stampit paths absent from the lock;
aliasing/build provenance remains unresolved. No stale-map conclusion is made.

The pinned publisher lock selects ieee754 1.2.1 and the bundle's extracted
license banner identifies ieee754. Its complete original BSD notice is retained
as a conservative supplement; source-map path/lock correlation alone does not
certify the exact emitted version. DOMPurify runtime version and extracted
license attribution identify 3.4.17 in Swagger and 3.4.13 in ReDoc; the selected
Apache-2.0 originals and attribution files remain beside unmodified banners.

Additional original notices cover Swagger base64-js/classnames and ReDoc
balanced-match/classnames/fast-deep-equal. ReDoc's three exact archive modules
match published map sourcesContent, a separate provenance fact rather than
proof of emission. neotraverse 1.0.1's archive matches publisher-lock SHA-512;
its distinctive diagnostic occurs in both original source and shipped Swagger
JS, and its full original MIT grant is retained. Exact transformed module
reconstruction and complete emitted dependency/notices reconciliation remain
outstanding. No source map or build tooling is shipped with runtime assets.

Nine further complete original package notices supplement Swagger's abbreviated
buffer, safe-buffer, repeat-string, fast-json-patch, React/ReactDOM, scheduler,
use-sync-external-store and regenerator-runtime banners. Per-package archive and
banner evidence is recorded separately from the unqualified source-map census.

ReDoc banner notice reconciliation
Five further original grants supplement abbreviated ReDoc banners: Stickyfill,
perfect-scrollbar, mark.js, Prism and Lunr. Stickyfill's original also credits
Automattic; preserving only the extracted banner would omit that attribution.
Lunr is named in the worker banner and reports runtime version 2.3.9 in the embedded worker of the shipped
standalone bundle. Its separate publisher worker map is additional unqualified
input, not part of the standalone map census or accepted emitted closure. The
whole worker string matches byte-exactly in both original/shipped Blob inputs;
its hash and map provenance are retained without shipping another map or blob.
ReDoc React/ReactDOM/scheduler/react-is notices and use-sync-external-store 1.5.0
LICENSE bytes exactly match full originals already shipped under swagger-ui-dist;
components.json links those existing terms instead of copying duplicate files.
Both perfect-scrollbar 1.5.3 and 1.5.5 original dist files print version 1.5.3. The
1.5.5 archive source matches the published map input; this does not identify the
exact transformed emitted module. Original 1.5.5 LICENSE bytes are preserved.
redoc/banner-notice-provenance.json records archive integrity, source members,
full-notice associations and these limits. Other map-only candidates still need
actual emission/original-notice reconciliation; no complete legal/source or
emitted dependency inventory is certified. Existing banners and runtime assets
remain unchanged, and both backend classes copy the same combined notice bundle.
