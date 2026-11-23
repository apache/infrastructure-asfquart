#!/usr/bin/env python3
"""Tests that docs/reverse-proxy.md says what is so: its links lead somewhere, and what it says
that asfquart does and does not do is what asfquart does."""

import pathlib
import re

import asfquart

DOCS = pathlib.Path(__file__).parent.parent / "docs"
TEXT = (DOCS / "reverse-proxy.md").read_text(encoding="utf-8")


def _anchors(page):
    """The anchors of the headings of a page, as GitHub makes them"""
    headings = re.findall(r"^#+ (.+)$", (DOCS / page).read_text(encoding="utf-8"), flags=re.MULTILINE)
    return {re.sub(r"[^a-z0-9 _-]", "", heading.lower()).replace(" ", "-") for heading in headings}


def test_links_on_the_page_lead_somewhere():
    links = re.findall(r"\]\(([a-z-]+\.md)(?:#([a-z0-9-]+))?\)", TEXT)
    assert len(links) >= 4
    for page, anchor in links:
        assert (DOCS / page).is_file(), page
        if anchor:
            assert anchor in _anchors(page), f"{page}#{anchor}"


def test_page_is_linked_from_the_index():
    assert "(reverse-proxy.md)" in (DOCS / "README.md").read_text(encoding="utf-8")


async def test_asfquart_sends_no_hsts_header_and_a_secure_strict_cookie():
    """As the page says: the header is the proxy's, and the session cookie does not depend on it"""
    app = asfquart.construct("reverse_proxy_doc", token_file=None)

    @app.route("/test-login")
    async def test_login():
        asfquart.session.write({"uid": "testuser"})
        return "ok"

    client = app.test_client()
    resp = await client.get("/test-login", scheme="https")
    assert "Strict-Transport-Security" not in resp.headers
    (cookie,) = [value for value in resp.headers.getlist("Set-Cookie") if value.startswith("session=")]
    assert "Secure" in cookie and "SameSite=Strict" in cookie
    for path in ("/auth?login", "/auth", "/nowhere"):
        assert "Strict-Transport-Security" not in (await client.get(path, scheme="https")).headers


async def test_oauth_callback_address_is_https_even_for_a_plain_http_request():
    app = asfquart.construct("reverse_proxy_doc_callback", token_file=None)
    resp = await app.test_client().get("/auth?login", scheme="http", headers={"Host": "myapp.apache.org"})
    assert resp.status_code == 302
    assert "redirect_uri=https%3A//myapp.apache.org/auth" in resp.headers["Location"]
