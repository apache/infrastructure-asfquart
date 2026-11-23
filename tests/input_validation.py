#!/usr/bin/env python3
"""Tests that docs/input-validation.md describes the rules that the code applies.

The page has a table of the patterns and limits, and tables of examples. They are read from the
page and compared with the code.
The other tests here pin statements on the page that no other test covers."""

import importlib
import pathlib
import re

import pytest

import asfquart
import asfquart.auth
import asfquart.base
import asfquart.generics
import asfquart.ldap
import asfquart.session
import asfquart.utils

DOC = pathlib.Path(__file__).parent.parent / "docs" / "input-validation.md"
TEXT = DOC.read_text(encoding="utf-8")

_counter = iter(range(1_000_000))


def _table_after(sentence):
    """The rows of the first table after the given text on the page, as lists of cells, without
    the header. A cell that is wholly in backticks is given without them."""
    lines = TEXT[TEXT.index(sentence) :].splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("|"))
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split(" | ")]
        rows.append([cell[1:-1] if re.fullmatch(r"`[^`]*`", cell) else cell for cell in cells])
    assert rows, sentence
    return rows


def _examples(sentence):
    """(value, accepted) for each row of a table of examples"""
    return [(value, verdict.startswith("Yes")) for value, verdict in _table_after(sentence)]


def _resolve(name):
    """The object that a dotted name on the page refers to"""
    parts = name.split(".")
    for split in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:split]))
        except ModuleNotFoundError:
            continue
        for attr in parts[split:]:
            obj = getattr(obj, attr)
        return obj
    raise LookupError(name)


def _as_text(value):
    if isinstance(value, re.Pattern):
        return value.pattern
    if isinstance(value, tuple):
        return ", ".join(value)
    return str(value)


# ---- The table of values ----

VALUES = _table_after("## The values")


@pytest.mark.parametrize("name, value", VALUES, ids=[name for name, _ in VALUES])
def test_documented_value_is_the_value_in_the_code(name, value):
    assert _as_text(_resolve(name)) == value


def test_every_validation_constant_is_on_the_page():
    """The patterns and limits that the rules use are all in the table, so a new one is not forgotten"""
    documented = {name for name, _ in VALUES}
    for module in (asfquart.base, asfquart.generics, asfquart.ldap, asfquart.utils):
        for attr, value in vars(module).items():
            is_rule = isinstance(value, re.Pattern) and attr not in (
                "UID_RE",
                "GROUP_RE",
            )  # those two parse LDAP's answers
            is_limit = attr.startswith(("MAX_", "DEFAULT_MAX_"))
            if is_rule or is_limit:
                # The two that are left out limit what is kept in memory, and are in docs/limits.md
                kept_in_memory = attr in ("DEFAULT_LDAP_CACHE_MAX_ENTRIES", "MAX_FAILED_LOGIN_USERS")
                assert f"{module.__name__}.{attr}" in documented or kept_in_memory, attr


# ---- The tables of examples ----


@pytest.mark.parametrize("value, accepted", _examples("| Value | A user id? |"))
def test_user_id_examples(value, accepted):
    for rule in (asfquart.base.ASF_UID_RE, asfquart.generics.OAUTH_UID_RE, asfquart.ldap.VALID_UID_RE):
        assert bool(rule.fullmatch(value)) is accepted


@pytest.mark.parametrize("value, accepted", _examples("| Target | Accepted? |"))
def test_redirect_target_examples(value, accepted):
    assert asfquart.generics._is_local_redirect(value) is accepted


@pytest.mark.parametrize("value, accepted", _examples("A callback host is matched against a pattern"))
def test_callback_host_examples(value, accepted):
    if accepted:
        asfquart.generics._check_callback_host(value)
    else:
        with pytest.raises(ValueError):
            asfquart.generics._check_callback_host(value)


@pytest.mark.parametrize("value, accepted", _examples("| Value | Matches? |"))
async def test_file_name_examples(value, accepted):
    """Through a real route, as the converter's pattern is only part of what the router matches with"""
    app = asfquart.construct(f"test_input_validation_{next(_counter)}", token_file=None, oauth=False)

    @app.route("/files/<filename:name>")
    async def files(name):
        return {"name": list(name)}

    resp = await app.test_client().get(f"/files/{value}")
    assert resp.status_code == (200 if accepted else 404)


# ---- Statements on the page that no other test covers ----


def _app(**kwargs):
    app = asfquart.construct(f"test_input_validation_{next(_counter)}", token_file=None, **kwargs)

    @app.route("/test-login")
    async def test_login():
        asfquart.session.write({"uid": "testuser"})
        return "ok"

    @app.route("/test-whoami")
    async def test_whoami():
        session = await asfquart.session.read()
        return session.uid if session is not None else "nobody"

    @app.route("/test-form", methods=["POST"])
    async def test_form():
        return await asfquart.utils.formdata()

    return app


async def _text(resp):
    return (await resp.get_data()).decode()


async def test_redirect_target_is_checked_after_decoding():
    app = _app()
    client = app.test_client()
    for url in ("/auth?login=%2F%2Fexample.org", "/auth?login=%2F%5Cexample.org", "/auth?login=/a%0Ab"):
        resp = await client.get(url, scheme="https")
        assert resp.status_code == 400
        assert await _text(resp) == "Invalid redirect URI.\n"


async def test_logout_with_a_refused_target_still_logs_out():
    app = _app()
    client = app.test_client()
    await client.get("/test-login", scheme="https")
    assert await _text(await client.get("/test-whoami", scheme="https")) == "testuser"
    resp = await client.post("/auth?logout=//example.org", scheme="https")
    assert resp.status_code == 400
    assert "Location" not in resp.headers
    assert await _text(await client.get("/test-whoami", scheme="https")) == "nobody"


@pytest.mark.parametrize("url", ["/auth?code=abc", "/auth?state=abc", "/auth?code=&state=abc", "/auth?code=abc&state="])
async def test_callback_needs_a_code_and_a_state(url):
    """Without both, the request is not a callback: it asks to see the session, and there is none"""
    resp = await _app().test_client().get(url, scheme="https")
    assert resp.status_code == 404


@pytest.mark.parametrize("header", ["Digest abc", "Negotiate xyz", 'Digest username="x", realm="y"'])
async def test_authorization_scheme_that_is_not_implemented(header):
    resp = await _app().test_client().get("/test-whoami", scheme="https", headers={"Authorization": header})
    assert resp.status_code == 501
    assert await _text(resp) == "Not implemented yet"


async def test_authorization_header_that_cannot_be_parsed_is_ignored():
    resp = (
        await _app().test_client().get("/test-whoami", scheme="https", headers={"Authorization": "Basic !!!not-base64"})
    )
    assert resp.status_code == 200
    assert await _text(resp) == "nobody"


async def test_basic_authentication_turned_off():
    app = _app(basic_auth=False)
    resp = await app.test_client().get(
        "/test-whoami", scheme="https", headers={"Authorization": "Basic dGVzdHVzZXI6cHc="}
    )
    assert resp.status_code == 401
    assert await _text(resp) == "Basic authentication is not enabled"


async def test_authorization_header_is_not_looked_at_when_there_is_a_session_cookie():
    """A request with a session in its cookie is handled by the cookie, even if that session has ended"""
    app = _app()
    client = app.test_client()
    assert (
        await client.get("/test-whoami", scheme="https", headers={"Authorization": "Digest abc"})
    ).status_code == 501
    await client.get("/test-login", scheme="https")
    resp = await client.get("/test-whoami", scheme="https", headers={"Authorization": "Digest abc"})
    assert resp.status_code == 200
    assert await _text(resp) == "testuser"
    async with client.session_transaction(scheme="https") as stored:
        stored[app.app_id] = {**stored[app.app_id], "uts": 0}  # long ago: the session has ended
    resp = await client.get("/test-whoami", scheme="https", headers={"Authorization": "Digest abc"})
    assert resp.status_code == 200
    assert await _text(resp) == "nobody"


@pytest.mark.parametrize("entry", ["a string", 42, ["a", "list"], None])
async def test_cookie_entry_that_is_not_a_dictionary_is_no_session(entry):
    app = _app()
    client = app.test_client()
    async with client.session_transaction(scheme="https") as stored:
        stored[app.app_id] = entry
    assert await _text(await client.get("/test-whoami", scheme="https")) == "nobody"


@pytest.mark.parametrize("uts", ["1700000000", True, None, [1]])
async def test_timestamp_that_is_not_a_number_is_treated_as_missing(uts):
    """With no usable time of last use, a session has ended"""
    app = _app()
    client = app.test_client()
    await client.get("/test-login", scheme="https")
    async with client.session_transaction(scheme="https") as stored:
        stored[app.app_id] = {**stored[app.app_id], "uts": uts}
    assert await _text(await client.get("/test-whoami", scheme="https")) == "nobody"


async def test_formdata_merges_query_form_and_json_and_checks_none_of_it():
    app = _app()
    client = app.test_client()
    resp = await client.post("/test-form?a=query&b=query", form={"b": "form", "c": "<script>"})
    assert await resp.get_json() == {"a": "query", "b": "form", "c": "<script>"}
    resp = await client.post("/test-form?a=query", json={"a": {"nested": [1, 2]}, "d": None})
    assert await resp.get_json() == {"a": {"nested": [1, 2]}, "d": None}


async def test_json_body_that_is_not_json_is_a_400():
    resp = (
        await _app().test_client().post("/test-form", data=b"{not json", headers={"Content-Type": "application/json"})
    )
    assert resp.status_code == 400


@pytest.mark.parametrize("body", [b"[1, 2]", b'[["a", 1]]', b'"text"', b"5", b"true", b"null"])
async def test_json_body_that_is_not_an_object_is_a_400(body):
    app = _app()
    app.config["PROPAGATE_EXCEPTIONS"] = False  # an error in the endpoint would be a 500, not raised here
    resp = await app.test_client().post("/test-form", data=body, headers={"Content-Type": "application/json"})
    assert resp.status_code == 400


@pytest.mark.parametrize("value", [1, "true", "yes", [True]])
def test_requirement_needs_true_itself(value):
    session = asfquart.session.ClientSession({"uid": "testuser", "isMember": value})
    assert asfquart.auth.Requirements.member(session)[0] is False
    session = asfquart.session.ClientSession({"uid": "testuser", "isMember": True})
    assert asfquart.auth.Requirements.member(session)[0] is True


def test_page_is_linked_from_the_index():
    assert "(input-validation.md)" in (DOC.parent / "README.md").read_text(encoding="utf-8")
