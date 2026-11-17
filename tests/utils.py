#!/usr/bin/env python3
"""Tests for utils.py"""

import asyncio
import itertools

import ezt
import pytest
import quart
import quart.formparser
import werkzeug.exceptions

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
MULTIPART = "multipart/form-data; boundary=xyz"
MULTIPART_BODY = (
    "--xyz\r\n"
    'Content-Disposition: form-data; name="a"\r\n\r\n'
    "hello\r\n"
    "--xyz\r\n"
    'Content-Disposition: form-data; name="upload"; filename="notes.txt"\r\n'
    "Content-Type: text/plain\r\n\r\n"
    "file contents\r\n"
    "--xyz--\r\n"
)


def _form_app(**config):
    """An app with one endpoint, which answers with the data that formdata() found"""
    app = asfquart.construct(f"test_formdata_{next(_form_counter)}", token_file=None)
    app.config.update(config)

    @app.route("/form", methods=["POST", "PUT"])
    async def form():
        data = await asfquart.utils.formdata()
        assert isinstance(data, dict)  # formdata() gives a dict, or raises
        result = {key: len(value) if isinstance(value, str) else value for key, value in data.items()}
        if quart.request.args.get("files"):
            # The rest of the request is still there for the endpoint, after formdata()
            files = await quart.request.files
            result["files"] = {name: len(upload.read()) for name, upload in files.items()}
        return result

    return app


async def _post_form(app, body, content_type=FORM, declare_length=True, path="/form"):
    headers = {"Content-Type": content_type}
    if declare_length:
        headers["Content-Length"] = str(len(body))
    return await app.test_client().post(path, data=body, headers=headers)


async def _assert_too_large(resp, limit):
    assert resp.status_code == 413
    assert f"larger than the {limit} bytes that are permitted" in (await resp.get_data()).decode()


@pytest.mark.utils
def test_form_content_types_match_quart():
    """The size check covers exactly the content types that quart parses as a form."""
    assert set(asfquart.utils.FORM_CONTENT_TYPES) == set(quart.formparser.FormDataParser.parse_functions)


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_reads_a_form(declare_length):
    """A form within the limit is read, with or without a Content-Length header."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=1000)
    resp = await _post_form(app, "a=" + "x" * 100 + "&b=yy", declare_length=declare_length, path="/form?q=zzz")
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 100, "b": 2, "q": 3}


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
@pytest.mark.parametrize("content_type", [
    FORM,
    MULTIPART,
    "application/x-url-encoded",
    "application/x-www-form-urlencoded; charset=utf-8",
    "Application/X-WWW-Form-Urlencoded",   # the type is not case sensitive, and quart parses this as a form
    "MULTIPART/FORM-DATA; boundary=xyz",
])
async def test_formdata_rejects_large_form(content_type, declare_length):
    """A form over the limit is a 413, however its content type is written."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=1000)
    resp = await _post_form(app, "a=" + "x" * 5000, content_type=content_type, declare_length=declare_length)
    await _assert_too_large(resp, 1000)


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_at_the_limit(declare_length):
    """The limit itself is allowed; one byte more is not."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=1000)
    assert (await _post_form(app, "a=" + "x" * 998, declare_length=declare_length)).status_code == 200
    assert (await _post_form(app, "a=" + "x" * 999, declare_length=declare_length)).status_code == 413


@pytest.mark.utils
async def test_formdata_raises_for_the_caller():
    """formdata() raises, and does not hand the endpoint a response in place of the dict."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=50)
    body = "a=" + "x" * 100
    headers = {"Content-Type": FORM, "Content-Length": str(len(body))}
    async with app.test_request_context("/form", method="POST", data=body, headers=headers):
        with pytest.raises(werkzeug.exceptions.RequestEntityTooLarge):
            await asfquart.utils.formdata()


# ---- formdata(): a form that declares its length is refused without reading its body ----

async def _stream_form(app, pieces, headers=None, complete=False):
    """Sends a form to the app piece by piece, as a slow client would, and returns the response.
    Unless complete is set, the client never says that it has finished sending."""
    headers = {"Content-Type": FORM, **(headers or {})}

    async def run():
        async with app.test_client().request("/form", method="POST", headers=headers) as connection:
            for piece in pieces:
                await connection.send(piece)
                await asyncio.sleep(0.01)
            if complete:
                await connection.send_complete()
        return await connection.as_response()

    # If the app waited for the rest of the body, this would not return
    return await asyncio.wait_for(run(), timeout=5)


@pytest.mark.utils
async def test_formdata_declared_length_is_refused_without_the_body():
    """The 413 comes while the client has sent only part of what it declared, and is still sending."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=1000)
    resp = await _stream_form(app, [b"a=" + b"x" * 100], headers={"Content-Length": "5000000"})
    assert resp.status_code == 413


# ---- formdata(): a form that does not declare its length is counted as it arrives ----

@pytest.mark.utils
async def test_formdata_undeclared_length_is_refused_at_the_limit():
    """Without a Content-Length, the 413 comes as soon as the limit is passed, not at the end of the body."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=1000)
    resp = await _stream_form(app, [b"a=" + b"x" * 600, b"x" * 600])  # past the limit, and not finished
    assert resp.status_code == 413


@pytest.mark.utils
async def test_formdata_undeclared_length_in_pieces():
    """A form that arrives in pieces, within the limit, is read whole."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=1000)
    resp = await _stream_form(app, [b"a=" + b"x" * 300, b"x" * 300 + b"&b=y", b"y"], complete=True)
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 600, "b": 2}


@pytest.mark.utils
async def test_formdata_undeclared_length_times_out():
    """A client that stops sending is given up on after quart's BODY_TIMEOUT, with a 408."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=1000, BODY_TIMEOUT=0.2)
    resp = await _stream_form(app, [b"a=" + b"x" * 100])  # and then nothing, without ending the body
    assert resp.status_code == 408


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_leaves_the_request_usable(declare_length):
    """After formdata(), the endpoint can still read the files of a multipart form."""
    app = _form_app()
    resp = await _post_form(app, MULTIPART_BODY, content_type=MULTIPART, declare_length=declare_length,
                            path="/form?files=1")
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 5, "files": {"upload": len("file contents")}}


# ---- formdata(): forms have a limit of their own, MAX_FORM_CONTENT_LENGTH ----

@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_default_form_limit(declare_length):
    """An app that sets nothing gets the default limit for forms, not quart's 16 MB for all bodies."""
    limit = asfquart.utils.DEFAULT_MAX_FORM_CONTENT_LENGTH
    assert limit == 102400
    assert (await _post_form(_form_app(), "a=" + "x" * (limit - 2), declare_length=declare_length)).status_code == 200
    resp = await _post_form(_form_app(), "a=" + "x" * (limit - 1), declare_length=declare_length)
    await _assert_too_large(resp, limit)


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_form_limit_setting(declare_length):
    """MAX_FORM_CONTENT_LENGTH sets the limit for forms, up or down."""
    small = _form_app(MAX_FORM_CONTENT_LENGTH=50)
    await _assert_too_large(await _post_form(small, "a=" + "x" * 100, declare_length=declare_length), 50)
    large = _form_app(MAX_FORM_CONTENT_LENGTH=1000000)
    resp = await _post_form(large, "a=" + "x" * 300000, declare_length=declare_length)
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 300000}


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_form_limit_none(declare_length):
    """MAX_FORM_CONTENT_LENGTH = None leaves only quart's limit for all bodies."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=None)
    resp = await _post_form(app, "a=" + "x" * 300000, declare_length=declare_length)
    assert resp.status_code == 200
    app = _form_app(MAX_CONTENT_LENGTH=1000, MAX_FORM_CONTENT_LENGTH=None)
    assert (await _post_form(app, "a=" + "x" * 5000, declare_length=declare_length)).status_code == 413


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_without_any_limit(declare_length):
    """With both settings None, there is no limit on a form."""
    app = _form_app(MAX_CONTENT_LENGTH=None, MAX_FORM_CONTENT_LENGTH=None)
    resp = await _post_form(app, "a=" + "x" * 500000, declare_length=declare_length)
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 500000}


@pytest.mark.utils
@pytest.mark.parametrize("declare_length", [True, False])
async def test_formdata_lower_limit_wins(declare_length):
    """A form is also a request body, so MAX_CONTENT_LENGTH applies when it is the lower of the two."""
    app = _form_app(MAX_CONTENT_LENGTH=1000, MAX_FORM_CONTENT_LENGTH=50000)
    resp = await _post_form(app, "a=" + "x" * 5000, declare_length=declare_length)
    assert resp.status_code == 413


@pytest.mark.utils
@pytest.mark.parametrize("value", ["1000", " 1000 ", 1000.0])
async def test_formdata_form_limit_from_a_string(value):
    """A limit read from the environment or a file may be a string; it is used as a number."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=value)
    assert (await _post_form(app, "a=" + "x" * 100)).status_code == 200
    await _assert_too_large(await _post_form(app, "a=" + "x" * 5000), 1000)


@pytest.mark.utils
async def test_formdata_form_limit_that_is_not_a_number():
    """A limit that cannot be used says which setting is wrong."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH="100 KB")
    headers = {"Content-Type": FORM, "Content-Length": "5"}
    async with app.test_request_context("/form", method="POST", data="a=xyz", headers=headers):
        with pytest.raises(ValueError, match="MAX_FORM_CONTENT_LENGTH"):
            await asfquart.utils.formdata()


@pytest.mark.utils
async def test_formdata_form_limit_does_not_apply_to_json():
    """The form limit is for forms: other bodies are limited by MAX_CONTENT_LENGTH alone."""
    app = _form_app(MAX_FORM_CONTENT_LENGTH=50)
    resp = await _post_form(app, '{"a": "' + "x" * 5000 + '", "n": 5}', content_type="application/json",
                            path="/form?q=zzz")
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": 5000, "n": 5, "q": 3}


# ---- JSON bodies ----

def _json_app():
    app = quart.Quart(f"test_formdata_{next(_form_counter)}")

    @app.route("/data", methods=["POST", "PUT"])
    async def data():
        return await asfquart.utils.formdata()

    return app


async def _send_json(app, body, method="POST", path="/data"):
    return await app.test_client().open(path, method=method, data=body, headers={"Content-Type": "application/json"})


@pytest.mark.utils
@pytest.mark.parametrize("method", ["POST", "PUT"])
async def test_formdata_reads_a_json_object(method):
    resp = await _send_json(_json_app(), b'{"a": [1, 2], "b": null, "q": "body"}', method=method, path="/data?q=query&r=1")
    assert resp.status_code == 200
    assert await resp.get_json() == {"a": [1, 2], "b": None, "q": "body", "r": "1"}


@pytest.mark.utils
async def test_formdata_reads_an_empty_json_object():
    resp = await _send_json(_json_app(), b"{}", path="/data?q=query")
    assert resp.status_code == 200
    assert await resp.get_json() == {"q": "query"}


@pytest.mark.utils
@pytest.mark.parametrize("body", [b"[1, 2]", b"[]", b'[["a", 1]]', b'["ab"]', b'"text"', b"5", b"0", b"1.5", b"true", b"false", b"null"])
async def test_formdata_refuses_json_that_is_not_an_object(body):
    """A list, a string, a number, a boolean or null is a 400, as a body that is not JSON is. It was a 500,
    or for some values (a list of pairs) was taken to be fields."""
    app = _json_app()
    app.config["PROPAGATE_EXCEPTIONS"] = False  # an error in the endpoint would be a 500, not raised here
    resp = await _send_json(app, body, path="/data?q=query")
    assert resp.status_code == 400
    assert "must be an object" in (await resp.get_data()).decode()


@pytest.mark.utils
@pytest.mark.parametrize("body", [b"{not json", b"", b"{'a': 1}"])
async def test_formdata_refuses_a_body_that_is_not_json(body):
    app = _json_app()
    app.config["PROPAGATE_EXCEPTIONS"] = False
    resp = await _send_json(app, body)
    assert resp.status_code == 400


@pytest.mark.utils
async def test_formdata_json_error_is_raised_for_the_caller():
    """The endpoint may catch it, as it may the one for a form that is too large"""
    app = quart.Quart(f"test_formdata_{next(_form_counter)}")

    @app.route("/data", methods=["POST"])
    async def data():
        try:
            return await asfquart.utils.formdata()
        except werkzeug.exceptions.BadRequest as e:
            return {"refused": e.description}, 422

    resp = await _send_json(app, b"[1, 2]")
    assert resp.status_code == 422
    assert await resp.get_json() == {"refused": "The JSON body of this request must be an object."}
