"""Same-origin API documentation with shipped browser runtime dependencies."""

import json
from html import escape
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles


def register_api_docs(app: FastAPI) -> None:
    """Register replacements after disabling FastAPI's CDN documentation pages."""
    app.mount(
        "/docs-assets",
        StaticFiles(directory=Path(__file__).parent / "static" / "api-docs"),
        name="api-docs-assets",
    )

    def urls(request: Request) -> tuple[str, str]:
        root = request.scope.get("root_path", "").rstrip("/")
        return root, root + "/docs-assets"

    @app.api_route("/docs", methods=["GET", "HEAD"], include_in_schema=False)
    async def swagger_ui(request: Request) -> HTMLResponse:
        root, assets = urls(request)
        return get_swagger_ui_html(
            openapi_url=root + app.openapi_url,
            title=escape(app.title) + " - Swagger UI",
            swagger_js_url=assets + "/swagger-ui-bundle.js",
            swagger_css_url=assets + "/swagger-ui.css",
            swagger_favicon_url=assets + "/favicon.svg",
            oauth2_redirect_url=root + app.swagger_ui_oauth2_redirect_url,
            init_oauth=app.swagger_ui_init_oauth,
            swagger_ui_parameters={"validatorUrl": None, "persistAuthorization": False},
        )

    @app.api_route(
        "/docs/oauth2-redirect", methods=["GET", "HEAD"], include_in_schema=False
    )
    async def swagger_oauth_redirect() -> HTMLResponse:
        return get_swagger_ui_oauth2_redirect_html()

    @app.api_route("/redoc", methods=["GET", "HEAD"], include_in_schema=False)
    async def redoc(request: Request) -> HTMLResponse:
        root, assets = urls(request)
        response = get_redoc_html(
            openapi_url=root + app.openapi_url,
            title=escape(app.title) + " - ReDoc",
            redoc_js_url=assets + "/redoc.standalone.js",
            redoc_favicon_url=assets + "/favicon.svg",
            with_google_fonts=False,
        )
        theme = json.dumps(
            {
                "typography": {
                    "fontFamily": "system-ui, sans-serif",
                    "headings": {"fontFamily": "system-ui, sans-serif"},
                    "code": {"fontFamily": "ui-monospace, monospace"},
                }
            }
        )
        html = response.body.decode().replace(
            "<redoc spec-url=",
            f"<redoc theme='{escape(theme, quote=True)}' spec-url=",
        )
        return HTMLResponse(html)
