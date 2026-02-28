#!/usr/bin/env python3
"""Tests for generics.py — redirect URI validation (CWE-601, CWE-79)"""

import itertools

import pytest
import quart

import asfquart


# Counter for unique app names to avoid duplicate route registration
_counter = itertools.count()


def _make_app():
    """Create a minimal Quart app with the OAuth endpoint for testing.
    asfquart.construct() calls setup_oauth() internally when oauth=True (the default),
    so we do NOT call setup_oauth() again here.
    """
    name = f"test_generics_{next(_counter)}"
    app = asfquart.construct(name, token_file=None)
    return app


# ---- Endpoint integration tests ----

@pytest.mark.generics
async def test_login_with_valid_redirect():
    """?login=/dashboard should initiate OAuth flow (302 to oauth.apache.org)."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=/dashboard")
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert "oauth.apache.org" in location


@pytest.mark.generics
async def test_login_bare():
    """Bare ?login (no redirect value) should initiate OAuth flow normally."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login")
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert "oauth.apache.org" in location


@pytest.mark.generics
async def test_login_rejects_javascript_uri():
    """?login=javascript:... must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=javascript:alert(1)")
        assert resp.status_code == 400
        body = (await resp.get_data()).decode()
        assert "Invalid redirect" in body


@pytest.mark.generics
async def test_login_rejects_absolute_url():
    """?login=https://evil.com must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=https://evil.com")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_login_rejects_protocol_relative():
    """?login=//evil.com must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=//evil.com")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_login_rejects_data_uri():
    """?login=data:text/html,... must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?login=data:text/html,<script>alert(1)</script>")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_logout_rejects_javascript_uri():
    """?logout=javascript:... must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout=javascript:alert(1)")
        assert resp.status_code == 400
        body = (await resp.get_data()).decode()
        assert "Invalid redirect" in body


@pytest.mark.generics
async def test_logout_rejects_absolute_url():
    """?logout=https://evil.com must return 400."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout=https://evil.com")
        assert resp.status_code == 400


@pytest.mark.generics
async def test_logout_bare():
    """Bare ?logout (no redirect value) should clear session and return 200."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout")
        assert resp.status_code == 200
        body = (await resp.get_data()).decode()
        assert "goodbye" in body.lower()


@pytest.mark.generics
async def test_logout_with_valid_redirect():
    """?logout=/goodbye should clear session and redirect."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth?logout=/goodbye")
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert "/goodbye" in location


@pytest.mark.generics
async def test_no_session_returns_404():
    """Bare /auth with no session should return 404."""
    app = _make_app()
    async with app.test_app():
        client = app.test_client()
        resp = await client.get("/auth")
        assert resp.status_code == 404
