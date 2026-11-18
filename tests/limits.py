#!/usr/bin/env python3
"""Tests that docs/limits.md gives the limits that the code applies.

The page has a table of the limits that are values in the code, and one of quart's settings.
Both are read from the page and compared with the code and with a real app. The other tests
here pin statements on the page that no other test covers."""

import importlib
import inspect
import pathlib
import re
import secrets
import time
import warnings

import pytest
import quart

import asfquart
import asfquart.base
import asfquart.generics
import asfquart.ldap
import asfquart.session
import asfquart.utils

DOC = pathlib.Path(__file__).parent.parent / "docs" / "limits.md"
TEXT = DOC.read_text(encoding="utf-8")
DAY = 86400

_counter = iter(range(1_000_000))


def _table_after(sentence):
    """The rows of the first table after the given text on the page, as lists of cells without
    their backticks, and without the header"""
    lines = TEXT[TEXT.index(sentence):].splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("|"))
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip().strip("`") for cell in line.strip().strip("|").split(" | ")])
    assert rows, sentence
    return rows


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


def _app(**kwargs):
    app = asfquart.construct(f"test_limits_{next(_counter)}", token_file=None, **kwargs)

    @app.route("/test-login")
    async def test_login():
        # Random padding, as the session is compressed before it goes into the cookie
        asfquart.session.write({"uid": "testuser", "padding": secrets.token_hex(int(quart.request.args.get("padding", 0)))})
        return "ok"

    @app.route("/test-whoami")
    async def test_whoami():
        session = await asfquart.session.read()
        return session.uid if session is not None else "nobody"

    @app.route("/test-form", methods=["POST"])
    async def test_form():
        return {"fields": len(await asfquart.utils.formdata())}

    return app


async def _whoami(client):
    return (await (await client.get("/test-whoami", scheme="https")).get_data()).decode()


@pytest.fixture
def clock(monkeypatch):
    """Lets a test move time on"""
    class Clock:
        now = time.time()

    monkeypatch.setattr(time, "time", lambda: Clock.now)
    return Clock


# ---- The tables of values ----

VALUES = _table_after("## The values")
QUART_SETTINGS = _table_after("And those that are quart's settings")


@pytest.mark.parametrize("name, value", VALUES, ids=[name for name, _ in VALUES])
def test_documented_value_is_the_value_in_the_code(name, value):
    assert str(_resolve(name)) == value


@pytest.mark.parametrize("setting, value", QUART_SETTINGS, ids=[name for name, _ in QUART_SETTINGS])
def test_documented_quart_setting_is_what_an_app_has(setting, value):
    assert str(_app().config[setting]) == value


def test_every_limit_in_the_code_is_on_the_page():
    """A limit that is added to the code has to be added to the page"""
    documented = {name for name, _ in VALUES}
    words = ("MAX_", "TIMEOUT", "TTL", "INTERVAL", "LIMIT")
    for module in (asfquart.base, asfquart.generics, asfquart.ldap, asfquart.session, asfquart.utils):
        for attr, value in vars(module).items():
            if attr.isupper() and any(word in attr for word in words) and not inspect.ismodule(value):
                name = f"{module.__name__}.{attr}"
                assert any(entry == name or entry.startswith(name + ".") for entry in documented), name


def test_documented_numbers_are_in_the_tables_of_limits():
    """The tables that describe the limits give the same numbers as the table of values"""
    for number in ("900 seconds", "10,000", "2,048", "10 seconds", "15 seconds", "30 seconds", "7 days", "60 seconds",
                   "31 days", "102,400 bytes", "16 MB", "1,000", "500,000 bytes", "3,600 seconds", "5 seconds", "`0600`"):
        assert number in TEXT[:TEXT.index("## The values")], number
    assert asfquart.session.DEFAULT_MAX_SESSION_IDLE == asfquart.session.DEFAULT_MAX_SESSION_AGE == 7 * DAY
    assert _app().config["MAX_CONTENT_LENGTH"] == 16 * 1024 * 1024
    assert asfquart.base.SECRETS_FILE_MODE == 0o600


# ---- Statements on the page that no other test covers ----

def test_workflow_timeout_default():
    assert inspect.signature(asfquart.generics.setup_oauth).parameters["workflow_timeout"].default == 900


@pytest.mark.parametrize("workflow_timeout", [900, 120])
async def test_state_cookie_lasts_as_long_as_the_login_may_take(workflow_timeout):
    app = asfquart.construct(f"test_limits_{next(_counter)}", token_file=None, oauth=False)
    asfquart.generics.setup_oauth(app, workflow_timeout=workflow_timeout)
    resp = await app.test_client().get("/auth?login", scheme="https")
    (cookie,) = [value for value in resp.headers.getlist("Set-Cookie") if value.startswith("asfquart-oauth-state=")]
    assert f"Max-Age={workflow_timeout};" in cookie


async def test_session_cookie_ends_with_the_browser_and_has_its_flags():
    resp = await _app().test_client().get("/test-login", scheme="https")
    (cookie,) = [value for value in resp.headers.getlist("Set-Cookie") if value.startswith("session=")]
    assert "Max-Age" not in cookie and "Expires" not in cookie
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie


@pytest.mark.parametrize("days, who", [(30, "testuser"), (32, "nobody")])
async def test_cookie_signature_older_than_31_days_is_not_accepted(clock, days, who):
    """quart's own limit, which applies even with both of asfquart's set to none"""
    app = _app()
    app.cfg["MAX_SESSION_IDLE"] = 0
    app.cfg["MAX_SESSION_AGE"] = 0
    client = app.test_client()
    await client.get("/test-login", scheme="https")
    clock.now += days * DAY
    assert await _whoami(client) == who


async def test_session_in_use_does_not_run_into_the_signature_limit(clock):
    """The cookie is signed again when asfquart saves it, so only an unused session reaches 31 days"""
    app = _app()
    app.cfg["MAX_SESSION_IDLE"] = 0
    app.cfg["MAX_SESSION_AGE"] = 0
    client = app.test_client()
    await client.get("/test-login", scheme="https")
    for _ in range(8):
        clock.now += 10 * DAY
        assert await _whoami(client) == "testuser"


@pytest.mark.parametrize("padding, warned", [(1000, False), (3000, True)])
async def test_session_too_large_for_a_cookie_is_warned_about(padding, warned):
    """A session of about 2 KB fits; one of about 6 KB does not, and a UserWarning says so"""
    app = _app()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await app.test_client().get(f"/test-login?padding={padding}", scheme="https")
    too_large = [w for w in caught if issubclass(w.category, UserWarning) and "cookie is too large" in str(w.message)]
    assert bool(too_large) is warned


def test_sizes_of_the_random_values():
    """A session id is 20 random bytes, and a generated application secret 32"""
    assert len(asfquart.session._generate_sid()) == 27  # 20 bytes, in the URL-safe base64 alphabet
    assert len(_app().secret_key) == 64                 # 32 bytes, in hex
    assert re.fullmatch(r"[0-9a-f]{64}", _app().secret_key)


def _multipart(fields):
    boundary = "limitsboundary"
    body = "".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n' for name, value in fields)
    return (body + f"--{boundary}--\r\n").encode(), f"multipart/form-data; boundary={boundary}"


async def test_multipart_form_with_too_many_fields():
    app = _app()
    app.config["MAX_FORM_CONTENT_LENGTH"] = None
    app.config["PROPAGATE_EXCEPTIONS"] = False
    body, content_type = _multipart([(f"f{i}", "v") for i in range(1000)])
    resp = await app.test_client().post("/test-form", data=body, headers={"Content-Type": content_type})
    assert (resp.status_code, await resp.get_json()) == (200, {"fields": 1000})
    body, content_type = _multipart([(f"f{i}", "v") for i in range(1001)])
    resp = await app.test_client().post("/test-form", data=body, headers={"Content-Type": content_type})
    assert resp.status_code == 413


async def test_multipart_form_with_fields_that_are_too_large():
    app = _app()
    app.config["MAX_FORM_CONTENT_LENGTH"] = None
    app.config["PROPAGATE_EXCEPTIONS"] = False
    # The limit is on each field, not on the fields together
    body, content_type = _multipart([("a", "x" * 400_000), ("b", "x" * 400_000)])
    assert (await app.test_client().post("/test-form", data=body, headers={"Content-Type": content_type})).status_code == 200
    body, content_type = _multipart([("a", "x" * 600_000)])
    assert (await app.test_client().post("/test-form", data=body, headers={"Content-Type": content_type})).status_code == 413
    # And on multipart forms only
    resp = await app.test_client().post("/test-form", data=b"a=" + b"x" * 600_000, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert resp.status_code == 200


async def test_logging_in_elsewhere_does_not_end_a_session():
    """There is no limit on how many sessions a user has"""
    app = _app()
    first, second = app.test_client(), app.test_client()
    await first.get("/test-login", scheme="https")
    await second.get("/test-login", scheme="https")
    assert await _whoami(first) == "testuser"
    assert await _whoami(second) == "testuser"


def test_no_time_limit_is_set_on_ldap():
    """As the page says. If one is added, the page should give it."""
    source = inspect.getsource(asfquart.ldap).lower()
    assert "timeout" not in source


def test_page_is_linked_from_the_index():
    index = (DOC.parent / "README.md").read_text(encoding="utf-8")
    assert "(limits.md)" in index
