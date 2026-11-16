import os.path

import asfquart


def test_no_token_file(tmp_path):
    app = asfquart.construct("foobar", app_dir=str(tmp_path), token_file=None)

    assert app.token_path is None
    assert os.path.exists(tmp_path / "apptoken.txt") is False


def test_default_token_file(tmp_path):
    app = asfquart.construct("foobar", app_dir=str(tmp_path))

    assert str(app.token_path) == str(app.app_dir / "apptoken.txt")
    assert os.path.exists(tmp_path / "apptoken.txt") is True
    app.token_path.unlink()


def test_absolute_token_file(tmp_path):
    app = asfquart.construct("foobar", token_file=str(tmp_path / "secret.txt"))

    assert str(app.token_path) == str(tmp_path / "secret.txt")
    assert os.path.exists(app.app_dir / "apptoken.txt") is False
    assert os.path.exists(app.app_dir / "secret.txt") is False
    assert os.path.exists(tmp_path / "secret.txt") is True
    app.token_path.unlink()


# ---- An empty token file is treated as missing ----

import logging
import os
import re
import stat

import pytest
import quart
import quart.globals

import asfquart.session


@pytest.fixture
def real_session(monkeypatch):
    """Other tests replace quart.session with a plain dict; these need the session cookie."""
    monkeypatch.setattr(quart, "session", quart.globals.session)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.mark.parametrize("content", ["", "\n", "  \n\t\n"])
def test_empty_token_file_is_regenerated(tmp_path, caplog, content):
    """A token file with nothing in it is not used as the secret: a new one is generated and saved."""
    token_file = tmp_path / "apptoken.txt"
    token_file.write_text(content)
    os.chmod(token_file, 0o600)

    app = asfquart.construct("foobar", app_dir=str(tmp_path))
    assert re.fullmatch(r"[0-9a-f]{64}", app.secret_key)
    assert token_file.read_text() == app.secret_key
    assert _mode(token_file) == 0o600
    assert "is empty; generating a new secret" in caplog.text
    assert app.secret_key not in caplog.text

    # The next start reads what was saved
    caplog.clear()
    again = asfquart.construct("foobar", app_dir=str(tmp_path))
    assert again.secret_key == app.secret_key
    assert "is empty" not in caplog.text


def test_empty_token_file_with_loose_permissions_is_tightened(tmp_path):
    token_file = tmp_path / "apptoken.txt"
    token_file.write_text("")
    os.chmod(token_file, 0o644)
    app = asfquart.construct("foobar", app_dir=str(tmp_path))
    assert token_file.read_text() == app.secret_key
    assert _mode(token_file) == 0o600


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write to a read-only file")
def test_empty_token_file_that_cannot_be_written(tmp_path, caplog):
    """If the new secret cannot be saved, the app still gets one, and the log says that it will not last."""
    token_file = tmp_path / "apptoken.txt"
    token_file.write_text("")
    os.chmod(token_file, 0o400)
    app = asfquart.construct("foobar", app_dir=str(tmp_path))
    assert re.fullmatch(r"[0-9a-f]{64}", app.secret_key)
    assert token_file.read_text() == ""
    assert "Session permanence cannot be guaranteed" in caplog.text


def test_token_file_with_a_secret_is_left_alone(tmp_path, caplog):
    token_file = tmp_path / "apptoken.txt"
    token_file.write_text("a-secret-that-was-put-there-by-hand\n")
    os.chmod(token_file, 0o600)
    app = asfquart.construct("foobar", app_dir=str(tmp_path))
    assert app.secret_key == "a-secret-that-was-put-there-by-hand\n"   # used as it is, newline and all
    assert token_file.read_text() == "a-secret-that-was-put-there-by-hand\n"
    assert "is empty" not in caplog.text


# ---- What docs/app-secret.md says an application can do ----

def _login_app(**kwargs):
    app = asfquart.construct("foobar", oauth=False, **kwargs)

    @app.route("/login")
    async def login():
        asfquart.session.write({"uid": "testuser"})
        return "ok"

    @app.route("/whoami")
    async def whoami():
        session = await asfquart.session.read()
        return {"uid": session.uid if session else None}

    return app


async def _logged_in_cookie(app):
    """Logs in, and returns the client, which holds the session cookie"""
    client = app.test_client()
    assert (await client.get("/login", scheme="https")).status_code == 200
    assert (await (await client.get("/whoami", scheme="https")).get_json()) == {"uid": "testuser"}
    return client


async def test_sessions_survive_a_restart_with_a_token_file(tmp_path, real_session):
    """The secret is read back from the file, so a cookie from before a restart is still accepted."""
    before = _login_app(app_dir=str(tmp_path))
    client = await _logged_in_cookie(before)
    after = _login_app(app_dir=str(tmp_path))
    assert after.secret_key == before.secret_key
    client.app = after
    assert (await (await client.get("/whoami", scheme="https")).get_json()) == {"uid": "testuser"}


async def test_sessions_do_not_survive_a_restart_without_a_token_file(tmp_path, real_session):
    before = _login_app(app_dir=str(tmp_path), token_file=None)
    client = await _logged_in_cookie(before)
    after = _login_app(app_dir=str(tmp_path), token_file=None)
    assert after.secret_key != before.secret_key
    client.app = after
    assert (await (await client.get("/whoami", scheme="https")).get_json()) == {"uid": None}


async def test_rotating_the_secret_logs_everybody_out(tmp_path, real_session):
    """Removing the token file and restarting gives a new secret, and cookies signed with the old one are refused."""
    before = _login_app(app_dir=str(tmp_path))
    client = await _logged_in_cookie(before)
    before.token_path.unlink()
    after = _login_app(app_dir=str(tmp_path))
    assert after.secret_key != before.secret_key
    assert _mode(after.token_path) == 0o600
    client.app = after
    assert (await (await client.get("/whoami", scheme="https")).get_json()) == {"uid": None}
    # and logging in again works
    assert (await client.get("/login", scheme="https")).status_code == 200
    assert (await (await client.get("/whoami", scheme="https")).get_json()) == {"uid": "testuser"}


async def test_application_can_supply_its_own_secret(tmp_path, real_session):
    """With token_file=None, an application can set app.secret_key itself, and keep it where it likes."""
    own_secret = "0123456789abcdef" * 4
    before = _login_app(app_dir=str(tmp_path), token_file=None)
    before.secret_key = own_secret
    client = await _logged_in_cookie(before)
    assert not (tmp_path / "apptoken.txt").exists()

    after = _login_app(app_dir=str(tmp_path), token_file=None)
    after.secret_key = own_secret          # the same secret again, from wherever the application keeps it
    client.app = after
    assert (await (await client.get("/whoami", scheme="https")).get_json()) == {"uid": "testuser"}


async def test_loading_config_can_remove_the_secret(tmp_path, real_session):
    """config.from_object() replaces the secret with the object's SECRET_KEY, None included. Keeping
    the secret across the call, as docs/app-secret.md shows, avoids that."""
    class Settings:
        SECRET_KEY = None
        SOME_SETTING = "value"

    app = _login_app(app_dir=str(tmp_path))
    app.config.from_object(Settings)
    assert app.secret_key is None           # the trap

    app = _login_app(app_dir=str(tmp_path))
    secret_key = app.secret_key
    app.config.from_object(Settings)
    app.secret_key = secret_key             # the way round it
    assert app.config["SOME_SETTING"] == "value"
    await _logged_in_cookie(app)
