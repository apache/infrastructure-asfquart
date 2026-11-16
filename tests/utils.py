#!/usr/bin/env python3
"""Tests for utils.py"""

import itertools

import ezt
import pytest
import quart

import asfquart.utils


def _template(text):
    t = ezt.Template()
    t.parse(text)
    return t


@pytest.mark.utils
async def test_use_template_renders_data():
    """A handler's data dictionary is rendered through the template."""

    @asfquart.utils.use_template(_template("Hello [name]"))
    async def page():
        return {"name": "world"}

    assert await page() == "Hello world"


@pytest.mark.utils
async def test_use_template_passes_response_through():
    """A handler's Response (a redirect, say) is returned as it is, not rendered."""

    redirect = quart.Response("", status=302, headers={"Location": "/elsewhere"})

    @asfquart.utils.use_template(_template("Hello [name]"))
    async def page():
        return redirect

    assert await page() is redirect


# ---- formdata(): the size of a form is checked before the form is read ----

_form_counter = itertools.count()

FORM = "application/x-www-form-urlencoded"


def _form_app(max_content_length="unset", max_form_content_length="unset"):
    """An app with one endpoint, which answers with the data that formdata() found"""
    app = asfquart.construct(f"test_formdata_{next(_form_counter)}", token_file=None)
    if max_content_length != "unset":
        app.config["MAX_CONTENT_LENGTH"] = max_content_length
    if max_form_content_length != "unset":
        app.config["MAX_FORM_CONTENT_LENGTH"] = max_form_content_length

    @app.route("/form", methods=["POST", "PUT"])
    async def form():
        data = await asfquart.utils.formdata()
        if isinstance(data, quart.Response):
            return data
        return {key: len(value) if isinstance(value, str) else value for key, value in data.items()}

    return app


async def _post_form(app, body, content_type=FORM, declare_length=True, path="/form"):
    headers = {"Content-Type": content_type}
    if declare_length:
        headers["Content-Length"] = str(len(body))
    async with app.test_app():
        return await app.test_client().post(path, data=body, headers=headers)


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_reads_a_form(declare_length):
    """A form within the limit is read, with or without a Content-Length header."""
    app = _form_app(max_content_length=1000)
    resp = await _post_form(app, "a=" + "x" * 100 + "&b=yy", declare_length=declare_length, path="/form?q=zzz")
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 100, "b": 2, "q": 3}


@pytest.mark.utils
@pytest.mark.parametrize("content_type", [FORM, "multipart/form-data; boundary=xyz", "application/x-url-encoded"])
async def test_formdata_rejects_large_form_before_reading_it(content_type):
    """A form that declares a length over the limit gets the 413 from formdata() itself. Were the
    form read first, quart would raise its own error while reading, and answer with an HTML page."""
    app = _form_app(max_content_length=1000)
    resp = await _post_form(app, "a=" + "x" * 5000, content_type=content_type)
    assert resp.status_code == 413
    assert resp.content_type == "text/plain; charset=utf-8"
    body = (await resp.get_data()).decode()
    assert "5002 bytes" in body
    assert "1000 bytes" in body


@pytest.mark.utils
async def test_formdata_at_the_limit():
    """The limit itself is allowed; one byte more is not."""
    assert (await _post_form(_form_app(max_content_length=1000), "a=" + "x" * 998)).status_code == 200
    assert (await _post_form(_form_app(max_content_length=1000), "a=" + "x" * 999)).status_code == 413


@pytest.mark.utils
async def test_formdata_large_form_without_content_length():
    """With no declared length there is nothing to check up front; quart's limit stops the read.
    That is a 413, and not an error in formdata()."""
    app = _form_app(max_content_length=1000)
    resp = await _post_form(app, "a=" + "x" * 5000, declare_length=False)
    assert resp.status_code == 413


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_without_any_limit(declare_length):
    """With both settings None, there is no limit on a form."""
    app = _form_app(max_content_length=None, max_form_content_length=None)
    resp = await _post_form(app, "a=" + "x" * 500000, declare_length=declare_length)
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 500000}


# ---- formdata(): forms have a limit of their own, MAX_FORM_CONTENT_LENGTH ----

@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_default_form_limit(declare_length):
    """An app that sets nothing gets the default limit for forms, not quart's 16 MB for all bodies."""
    limit = asfquart.utils.DEFAULT_MAX_FORM_CONTENT_LENGTH
    assert limit == 102400
    assert (await _post_form(_form_app(), "a=" + "x" * (limit - 2), declare_length=declare_length)).status_code == 200
    resp = await _post_form(_form_app(), "a=" + "x" * (limit - 1), declare_length=declare_length)
    assert resp.status_code == 413
    assert resp.content_type == "text/plain; charset=utf-8"
    assert f"{limit + 1} bytes" in (await resp.get_data()).decode()
    assert f"({limit} bytes)" in (await resp.get_data()).decode()


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_form_limit_setting(declare_length):
    """MAX_FORM_CONTENT_LENGTH sets the limit for forms, up or down."""
    small = _form_app(max_form_content_length=50)
    assert (await _post_form(small, "a=" + "x" * 100, declare_length=declare_length)).status_code == 413
    large = _form_app(max_form_content_length=1000000)
    resp = await _post_form(large, "a=" + "x" * 300000, declare_length=declare_length)
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 300000}


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_form_limit_none(declare_length):
    """MAX_FORM_CONTENT_LENGTH = None leaves only quart's limit for all bodies."""
    app = _form_app(max_form_content_length=None)
    resp = await _post_form(app, "a=" + "x" * 300000, declare_length=declare_length)
    assert resp.status_code == 200
    assert (await _post_form(_form_app(max_content_length=1000, max_form_content_length=None),
                             "a=" + "x" * 5000, declare_length=declare_length)).status_code == 413


@pytest.mark.utils
async def test_formdata_lower_limit_wins():
    """A form is also a request body, so MAX_CONTENT_LENGTH applies when it is the lower of the two."""
    app = _form_app(max_content_length=1000, max_form_content_length=50000)
    resp = await _post_form(app, "a=" + "x" * 5000)
    assert resp.status_code == 413
    assert "(1000 bytes)" in (await resp.get_data()).decode()


@pytest.mark.utils
async def test_formdata_form_limit_does_not_apply_to_json():
    """The form limit is for forms: other bodies are limited by MAX_CONTENT_LENGTH alone."""
    app = _form_app(max_form_content_length=50)
    resp = await _post_form(app, '{"a": "' + "x" * 5000 + '"}', content_type="application/json")
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 5000}


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_reads_multipart(declare_length):
    """A multipart form is parsed, also when its length had to be measured first."""
    body = (
        "--xyz\r\n"
        'Content-Disposition: form-data; name="a"\r\n\r\n'
        "hello\r\n"
        "--xyz\r\n"
        'Content-Disposition: form-data; name="b"\r\n\r\n'
        "hi\r\n"
        "--xyz--\r\n"
    )
    resp = await _post_form(_form_app(), body, content_type="multipart/form-data; boundary=xyz",
                            declare_length=declare_length)
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 5, "b": 2}


@pytest.mark.utils
async def test_formdata_reads_json():
    """JSON is not a form, and is read as before."""
    app = _form_app(max_content_length=1000)
    resp = await _post_form(app, '{"a": "xyz", "n": 5}', content_type="application/json", path="/form?q=zzz")
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 3, "n": 5, "q": 3}
