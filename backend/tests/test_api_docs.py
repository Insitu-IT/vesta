"""Offline documentation routing, resource integrity and packaging contracts."""

import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api_docs import register_api_docs

BACKEND = Path(__file__).resolve().parents[1]


class Resources(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
        self.redoc_options = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("link", "script"):
            self.urls.extend(attrs[key] for key in ("href", "src") if key in attrs)
        if tag == "redoc":
            self.redoc_options = attrs


@pytest.mark.parametrize("root_path", ["", "/gateway"])
def test_docs_load_only_same_origin_resources_and_preserve_openapi_oauth(root_path):
    app = FastAPI(docs_url=None, redoc_url=None, root_path=root_path)
    register_api_docs(app)

    @app.get("/inventory")
    def inventory():
        return []

    with TestClient(app) as client:
        for route in ("/docs", "/redoc"):
            response = client.get(root_path + route)
            assert response.status_code == 200
            resources = Resources()
            resources.feed(response.text)
            assert len(resources.urls) >= 2
            for url in resources.urls:
                assert url.startswith(root_path + "/docs-assets/")
                asset = client.get(url)
                assert asset.status_code == 200
                assert len(asset.content) > 100
            assert "fonts.googleapis" not in response.text
            assert root_path + "/openapi.json" in response.text
            if route == "/docs":
                assert '"validatorUrl": null' in response.text
                assert root_path + "/docs/oauth2-redirect" in response.text
            else:
                assert "disable-search" not in resources.redoc_options
                typography = json.loads(resources.redoc_options["theme"])["typography"]
                assert typography["fontFamily"] == "system-ui, sans-serif"
        redirect = client.get(root_path + "/docs/oauth2-redirect")
        assert redirect.status_code == 200
        assert "window.opener.swaggerUIRedirectOauth2" in redirect.text
        for route in ("/docs", "/redoc", "/docs/oauth2-redirect"):
            head = client.head(root_path + route)
            assert head.status_code == 200
            assert head.content == b""
        schema = client.get(root_path + "/openapi.json").json()
        assert set(schema["paths"]) == {"/inventory"}
        assert client.get(root_path + "/docs-assets/../../app.py").status_code == 404


def test_vendored_docs_integrity_and_complete_runtime_inventory():
    manifest = json.loads((BACKEND / "notices/api-docs/manifest.json").read_text())
    assert {key: value["version"] for key, value in manifest["packages"].items()} == {
        "swagger-ui-dist": "5.34.1",
        "redoc": "2.5.4",
    }
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((BACKEND / name).read_bytes()).hexdigest() == digest, name
    assert set(p.name for p in (BACKEND / "static/api-docs").iterdir()) == {
        "swagger-ui-bundle.js",
        "swagger-ui.css",
        "redoc.standalone.js",
        "favicon.svg",
        "redocly-logo.svg",
    }
    redoc = (BACKEND / "static/api-docs/redoc.standalone.js").read_bytes()
    patch = manifest["packages"]["redoc"]["patches"][0]
    assert patch["find"].encode() not in redoc
    assert redoc.count(patch["replace"].encode()) == 1
    original = redoc.replace(patch["replace"].encode(), patch["find"].encode())
    assert hashlib.sha256(original).hexdigest() == patch["upstream_sha256"]
    assert (BACKEND / "static/api-docs/favicon.svg").read_bytes() == (
        BACKEND.parent / "frontend/public/assets/vesta-1-1-0/summer-light.svg"
    ).read_bytes()


def test_community_backend_payload_ships_assets_and_notices():
    dockerfile = (BACKEND / "Dockerfile").read_text()
    assert "api_docs.py" in dockerfile
    assert "COPY static/api-docs/ static/api-docs/" in dockerfile
    assert "COPY notices/api-docs/ /usr/share/licenses/vnbui/api-docs/" in dockerfile


@pytest.mark.parametrize("root_path", ["", "/gateway"])
def test_only_redoc_document_allows_its_local_search_worker(root_path):
    from middleware import SecurityHeadersMiddleware

    app = FastAPI(docs_url=None, redoc_url=None, root_path=root_path)
    register_api_docs(app)
    app.add_middleware(SecurityHeadersMiddleware)
    with TestClient(app) as client:
        for path in (
            "/docs",
            "/redoc",
            "/openapi.json",
            "/docs-assets/redoc.standalone.js",
        ):
            csp = client.get(root_path + path).headers["Content-Security-Policy"]
            assert "connect-src 'self';" in csp
            assert "font-src 'self' data:;" in csp
            assert ("worker-src 'self' blob:;" in csp) == (path == "/redoc")


def test_embedded_component_terms_are_associated_separately_from_hashes():
    notices = BACKEND / "notices/api-docs"
    graph = json.loads((notices / "swagger-ui-dist/build-graph.json").read_text())
    assert graph["selected_nodes"]["ieee754"]["version"] == "1.2.1"
    for package, version in (("swagger-ui-dist", "3.4.17"), ("redoc", "3.4.13")):
        inventory = json.loads((notices / package / "components.json").read_text())
        components = {
            component["name"]: component for component in inventory["components"]
        }
        purifier = components["dompurify"]
        assert purifier["version"] == version
        assert purifier["selected_license"] == "Apache-2.0"
        for name in purifier["notice_files"]:
            assert (notices / name).is_file()
        apache = (notices / purifier["notice_files"][0]).read_text()
        assert "TERMS AND CONDITIONS" in apache
        assert "END OF TERMS AND CONDITIONS" in apache
    ieee = (notices / "swagger-ui-dist/ieee754-1.2.1.LICENSE").read_text()
    assert "Copyright 2008 Fair Oaks Labs, Inc." in ieee
    assert "1. Redistributions of source code" in ieee
    assert "2. Redistributions in binary form" in ieee
    assert "3. Neither the name of the copyright holder" in ieee
    assert "THIS SOFTWARE IS PROVIDED" in ieee
