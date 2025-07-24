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
