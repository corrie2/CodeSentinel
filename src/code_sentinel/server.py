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
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
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

# Track background tasks to prevent GC and log unhandled exceptions
_background_tasks: set[asyncio.Task] = set()


def _task_done_callback(task: asyncio.Task) -> None:
    """Log unhandled exceptions from background tasks and remove from tracking."""
    _background_tasks.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.exception("Background audit task failed: %s", exc, exc_info=exc)


def create_app(
    webhook_secret: str = "",
    config: Config | None = None,
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
    x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(None, alias="X-GitHub-Event"),
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

    # Schedule audit with proper error tracking
    task = asyncio.create_task(
        _run_audit("github", owner, repo, number)
    )
    _background_tasks.add(task)
    task.add_done_callback(_task_done_callback)

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
    x_gitlab_token: str | None = Header(None, alias="X-Gitlab-Token"),
    x_gitlab_event: str | None = Header(None, alias="X-Gitlab-Event"),
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

    # Only process open/reopen/update actions
    if action not in ("open", "reopen", "update"):
        return JSONResponse(
            content={"message": f"Ignoring MR action: {action}"},
            status_code=202,
        )

    project = payload.get("project", {})
    # GitLab provides full_path like "group/subgroup/repo" — use as-is
    full_path = project.get("path_with_namespace", "")
    if not full_path or "/" not in full_path:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot parse project path: {full_path}",
        )
    # Split into owner (everything except last segment) and repo (last segment)
    # This handles nested namespaces: "group/subgroup/project" -> owner="group/subgroup", repo="project"
    parts = full_path.rsplit("/", 1)
    owner, repo = parts[0], parts[1]
    number = attrs.get("iid", 0)

    if not owner or not repo or not number:
        raise HTTPException(status_code=400, detail="Missing MR metadata in payload")

    logger.info("GitLab MR webhook received: %s/%s#%d (action=%s)", owner, repo, number, action)

    # Schedule audit with proper error tracking
    task = asyncio.create_task(
        _run_audit("gitlab", owner, repo, number)
    )
    _background_tasks.add(task)
    task.add_done_callback(_task_done_callback)

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


# ── Background Audit Pipeline ──────────────────────────────────────


async def _run_audit(provider_type: str, owner: str, repo: str, number: int) -> None:
    """Run the audit pipeline for a GitHub PR or GitLab MR.

    This runs in a background asyncio task.  Errors are logged but not
    propagated — the webhook has already returned 202.
    """
    try:
        from code_sentinel.review import review, ReviewOptions
        from code_sentinel.reporter.formatter import render_pr_comment, build_report_context, PRMetadata, ReviewResults

        cfg = _app_state.get("config")
        if provider_type == "gitlab":
            url = f"https://gitlab.com/{owner}/{repo}/-/merge_requests/{number}"
        else:
            url = f"https://github.com/{owner}/{repo}/pull/{number}"

        options = ReviewOptions(
            provider=getattr(cfg, "provider", "mimo") if cfg else "mimo",
            github_token=getattr(cfg, "github_token", None) if cfg else None,
            skip_llm=False,
        )
        result = await review(url, options=options)

        logger.info(
            "%s audit complete for %s/%s#%d: risk=%s score=%d findings=%d",
            provider_type.capitalize(),
            owner, repo, number,
            result.risk.level, result.risk.score,
            len(result.llm_review.findings),
        )

        # Post results back as a PR/MR comment
        comment_body = result.reports.get("pr-comment", "")
        if not comment_body:
            # Fallback: generate from result if reporter didn't run
            try:
                pr_meta = PRMetadata(
                    url=result.pr_url,
                    title=result.pr_title,
                    author=result.pr_author,
                    repo=result.repo,
                    number=number,
                    base_branch=result.base_branch,
                    head_branch=result.head_branch,
                )
                review_results = ReviewResults(
                    risk_level=result.risk.level,
                    risk_score=result.risk.score,
                    risk_details=result.risk.contributions,
                    deep_review=result.llm_review,
                    needs_attention=result.needs_attention,
                    recommendations=result.recommendations,
                )
                ctx = build_report_context(pr_meta, review_results)
                comment_body = render_pr_comment(ctx)
            except Exception as exc:
                logger.warning("Failed to render PR comment: %s", exc)
                comment_body = f"## CodeSentinel Review\n\nRisk Level: {result.risk.level} ({result.risk.score} points)\n\n{len(result.llm_review.findings)} findings detected."

        if comment_body:
            try:
                from code_sentinel.git_provider.github import GitHubProvider
                from code_sentinel.git_provider.gitlab import GitLabProvider

                if provider_type == "gitlab":
                    provider = GitLabProvider(cfg)
                else:
                    provider = GitHubProvider(cfg)

                async with provider:
                    prov_owner = f"{owner}/{repo}" if provider_type == "gitlab" else owner
                    prov_repo = "" if provider_type == "gitlab" else repo
                    posted = await provider.post_comment(prov_owner, prov_repo, number, comment_body)
                    if posted:
                        logger.info("Posted review comment on %s/%s#%d", owner, repo, number)
                    else:
                        logger.warning("Failed to post review comment on %s/%s#%d", owner, repo, number)
            except Exception as exc:
                logger.error("Error posting comment on %s/%s#%d: %s", owner, repo, number, exc)

    except Exception:
        logger.exception("Error in %s audit for %s/%s#%d", provider_type, owner, repo, number)
