"""
CodeSentinel Webhook Server.

FastAPI application that receives webhook events from GitHub and GitLab,
triggers audit pipelines in the background, and posts review results back
as PR/MR comments.

Endpoints
---------
POST /webhook/github   — GitHub pull-request webhook
POST /webhook/gitlab   — GitLab merge-request webhook
GET  /health           — Health check
GET  /                 — Info page
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from code_sentinel.config import Config

logger = logging.getLogger(__name__)

# ── FastAPI Application ────────────────────────────────────────────

app = FastAPI(
    title="CodeSentinel",
    description="Risk Advisor & Ecosystem Auditor — Webhook receiver for automated PR review",
    version="0.1.0",
)

# Shared state injected at startup
_app_state: dict[str, Any] = {
    "webhook_secret": "",
    "config": None,
}


def create_app(
    webhook_secret: str = "",
    config: Optional[Config] = None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Parameters
    ----------
    webhook_secret : str
        Shared secret for webhook signature verification.
    config : Config | None
        Application configuration.  Created from env if not provided.

    Returns
    -------
    FastAPI
        The configured application instance.
    """
    _app_state["webhook_secret"] = webhook_secret or os.environ.get(
        "CODESENTINEL_WEBHOOK_SECRET", ""
    )
    _app_state["config"] = config or Config()
    return app


# ── Routes ─────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def index():
    """Info page."""
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html>
<head><title>CodeSentinel</title></head>
<body style="font-family:system-ui,sans-serif;max-width:600px;margin:2rem auto;padding:0 1rem">
  <h1>CodeSentinel</h1>
  <p>Risk Advisor & Ecosystem Auditor &mdash; automated PR risk assessment and impact analysis.</p>
  <h2>Webhook Endpoints</h2>
  <table style="border-collapse:collapse;width:100%">
    <tr><td style="padding:4px 8px"><code>POST /webhook/github</code></td>
        <td style="padding:4px 8px">GitHub pull-request events</td></tr>
    <tr><td style="padding:4px 8px"><code>POST /webhook/gitlab</code></td>
        <td style="padding:4px 8px">GitLab merge-request events</td></tr>
    <tr><td style="padding:4px 8px"><code>GET /health</code></td>
        <td style="padding:4px 8px">Health check</td></tr>
  </table>
  <h2>Status</h2>
  <p>Service is running.</p>
</body>
</html>""",
        status_code=200,
    )


@app.get("/health")
async def health():
    """Health check endpoint."""
    return JSONResponse(
        content={
            "status": "healthy",
            "service": "codesentinel",
            "version": "0.1.0",
            "timestamp": int(time.time()),
        }
    )


# ── GitHub Webhook ─────────────────────────────────────────────────


@app.post("/webhook/github", status_code=202)
async def webhook_github(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
):
    """Handle GitHub webhook events.

    Expects ``pull_request`` events.  Verifies the HMAC-SHA256 signature
    if a webhook secret is configured.  Triggers the audit pipeline in
    the background and returns 202 Accepted immediately.
    """
    raw_body = await request.body()

    # Signature verification
    secret = _app_state.get("webhook_secret", "")
    if secret:
        if not x_hub_signature_256:
            raise HTTPException(status_code=401, detail="Missing signature header")
        if not _verify_github_signature(raw_body, secret, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid signature")

    # Only process pull_request events
    if x_github_event != "pull_request":
        return JSONResponse(
            content={"message": f"Ignoring event: {x_github_event}"},
            status_code=202,
        )

    # Parse payload
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action", "")
    # Only process opened, synchronize (new commits pushed), reopened
    if action not in ("opened", "synchronize", "reopened"):
        return JSONResponse(
            content={"message": f"Ignoring pull_request action: {action}"},
            status_code=202,
        )

    pr = payload.get("pull_request", {})
    repo_data = payload.get("repository", {})

    owner = repo_data.get("owner", {}).get("login", "")
    repo = repo_data.get("name", "")
    number = pr.get("number", 0)

    if not owner or not repo or not number:
        raise HTTPException(status_code=400, detail="Missing PR metadata in payload")

    logger.info("GitHub PR webhook received: %s/%s#%d (action=%s)", owner, repo, number, action)

    # Fire-and-forget the audit pipeline
    asyncio.create_task(
        _run_github_audit(owner=owner, repo=repo, number=number)
    )

    return JSONResponse(
        content={
            "message": "Audit queued",
            "provider": "github",
            "pr": f"{owner}/{repo}#{number}",
        },
        status_code=202,
    )


# ── GitLab Webhook ─────────────────────────────────────────────────


@app.post("/webhook/gitlab", status_code=202)
async def webhook_gitlab(
    request: Request,
    x_gitlab_token: Optional[str] = Header(None, alias="X-Gitlab-Token"),
    x_gitlab_event: Optional[str] = Header(None, alias="X-Gitlab-Event"),
):
    """Handle GitLab webhook events.

    Expects ``Merge Request Hook`` events.  Verifies the shared secret
    token if configured.  Triggers the audit pipeline in the background
    and returns 202 Accepted immediately.
    """
    raw_body = await request.body()

    # Token verification
    secret = _app_state.get("webhook_secret", "")
    if secret:
        if not x_gitlab_token:
            raise HTTPException(status_code=401, detail="Missing GitLab token header")
        if not hmac.compare_digest(x_gitlab_token, secret):
            raise HTTPException(status_code=401, detail="Invalid GitLab token")

    # Only process Merge Request Hook
    if x_gitlab_event != "Merge Request Hook":
        return JSONResponse(
            content={"message": f"Ignoring event: {x_gitlab_event}"},
            status_code=202,
        )

    # Parse payload
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    attrs = payload.get("object_attributes", {})
    action = attrs.get("action", "")
    state = attrs.get("state", "")

    # Only process open/reopen/update actions
    if action not in ("open", "reopen", "update"):
        return JSONResponse(
            content={"message": f"Igoring MR action: {action}"},
            status_code=202,
        )

    project = payload.get("project", {})
    # GitLab provides full_path like "group/repo"
    full_path = project.get("path_with_namespace", "")
    parts = full_path.split("/", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot parse project path: {full_path}",
        )
    owner, repo = parts[0], parts[1]
    number = attrs.get("iid", 0)

    if not owner or not repo or not number:
        raise HTTPException(status_code=400, detail="Missing MR metadata in payload")

    logger.info("GitLab MR webhook received: %s/%s#%d (action=%s)", owner, repo, number, action)

    # Fire-and-forget the audit pipeline
    asyncio.create_task(
        _run_gitlab_audit(owner=owner, repo=repo, number=number)
    )

    return JSONResponse(
        content={
            "message": "Audit queued",
            "provider": "gitlab",
            "mr": f"{owner}/{repo}#{number}",
        },
        status_code=202,
    )


# ── Signature Verification ─────────────────────────────────────────


def _verify_github_signature(
    body: bytes, secret: str, signature_header: str
) -> bool:
    """Verify a GitHub HMAC-SHA256 webhook signature.

    Parameters
    ----------
    body : bytes
        The raw request body.
    secret : str
        The configured webhook secret.
    signature_header : str
        The ``X-Hub-Signature-256`` header value (format: ``sha256=<hex>``).

    Returns
    -------
    bool
        True if the signature is valid.
    """
    if not signature_header:
        return False

    parts = signature_header.split("=", 1)
    if len(parts) != 2 or parts[0] != "sha256":
        return False

    expected = hmac.new(
        key=secret.encode("utf-8"),
        msg=body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(parts[1], expected)


# ── Background Audit Pipelines ─────────────────────────────────────


async def _run_github_audit(owner: str, repo: str, number: int) -> None:
    """Run the audit pipeline for a GitHub PR and post results.

    This runs in a background asyncio task.
    """
    try:
        from code_sentinel.review import review, ReviewOptions

        cfg = _app_state.get("config")
        pr_url = f"https://github.com/{owner}/{repo}/pull/{number}"
        options = ReviewOptions(
            provider=getattr(cfg, "provider", "mimo") if cfg else "mimo",
            github_token=getattr(cfg, "github_token", None) if cfg else None,
            skip_llm=False,
        )
        result = await review(pr_url, options=options)

        logger.info(
            "GitHub audit complete for %s/%s#%d: risk=%s score=%d findings=%d",
            owner, repo, number, result.risk.level, result.risk.score,
            len(result.llm_review.findings),
        )

        # TODO: Post results back as a PR comment

    except Exception:
        logger.exception("Error in GitHub audit for %s/%s#%d", owner, repo, number)


async def _run_gitlab_audit(owner: str, repo: str, number: int) -> None:
    """Run the audit pipeline for a GitLab MR and post results.

    This runs in a background asyncio task.
    """
    try:
        from code_sentinel.review import review, ReviewOptions

        cfg = _app_state.get("config")
        mr_url = f"https://gitlab.com/{owner}/{repo}/-/merge_requests/{number}"
        options = ReviewOptions(
            provider=getattr(cfg, "provider", "mimo") if cfg else "mimo",
            skip_llm=False,
        )
        result = await review(mr_url, options=options)

        logger.info(
            "GitLab audit complete for %s/%s#%d: risk=%s score=%d findings=%d",
            owner, repo, number, result.risk.level, result.risk.score,
            len(result.llm_review.findings),
        )

        # TODO: Post results back as an MR note

    except Exception:
        logger.exception("Error in GitLab audit for %s/%s#%d", owner, repo, number)
