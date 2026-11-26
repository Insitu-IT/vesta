"""Small real API for the docs browser gate; excluded from customer images.

Run with PYTHONPATH=backend:backend/tests uvicorn docs_browser_app:app.
The final-image acceptance also runs check_api_docs_browser.cjs against app:app.
"""

from fastapi import FastAPI

from api_docs import register_api_docs
from middleware import SecurityHeadersMiddleware

app = FastAPI(
    title="Offline API documentation acceptance", docs_url=None, redoc_url=None
)
register_api_docs(app)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/inventory", tags=["Inventory"], summary="List protected machines")
def inventory():
    return []
