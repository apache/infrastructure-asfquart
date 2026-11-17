#!/usr/bin/env python3
"""Miscellaneous helpers for ASFQuart"""

import os.path
import io
import functools
import asyncio
import logging

import quart
import werkzeug.exceptions
import werkzeug.routing
import werkzeug.sansio.response

LOGGER = logging.getLogger(__name__)

# The largest form, in bytes, that formdata() will read, unless the app sets MAX_FORM_CONTENT_LENGTH.
DEFAULT_MAX_FORM_CONTENT_LENGTH = 102400

# The content types that quart parses as a form. These are compared with the request's mimetype,
# which is lower case and has no parameters, as quart does when it picks a parser.
FORM_CONTENT_TYPES = (
    "multipart/form-data",
    "application/x-www-form-urlencoded",
    "application/x-url-encoded",
)


def _size_setting(name: str, default=None):
    """A size limit from the app's config, in bytes, or None if there is none. The value may be a
    string, as it is when the config was read from the environment."""
    value = quart.current_app.config.get(name, default)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"The {name} setting must be a number of bytes, or None; it is {value!r}") from None


def _max_form_content_length():
    """The largest form that formdata() will read, in bytes, or None if there is no limit.

    Forms have a limit of their own, the MAX_FORM_CONTENT_LENGTH setting, so that it can be small
    without also limiting other request bodies such as uploads. Quart's MAX_CONTENT_LENGTH applies
    to every request body, forms included, so the lower of the two is the limit for a form."""
    limits = (
        _size_setting("MAX_FORM_CONTENT_LENGTH", DEFAULT_MAX_FORM_CONTENT_LENGTH),
        _size_setting("MAX_CONTENT_LENGTH"),
    )
    limits = [limit for limit in limits if limit is not None]
    return min(limits) if limits else None


def _form_too_large(max_size: int) -> werkzeug.exceptions.RequestEntityTooLarge:
    return werkzeug.exceptions.RequestEntityTooLarge(
        f"The form data in this request is larger than the {max_size} bytes that are permitted."
    )


async def _receive_form_body(max_size: int):
    """Receives the body of a form that does not declare its length (chunked transfer encoding),
    and gives up as soon as it has grown past max_size, without receiving the rest."""
    request = quart.request
    chunks = []

    async def receive():
        size = 0
        async for chunk in request.body:
            size += len(chunk)
            if size > max_size:
                raise _form_too_large(max_size)
            chunks.append(chunk)

    # Iterating over the body has no time limit of its own, so the one that quart uses when it
    # reads a body is applied here, for a client that stops sending.
    try:
        await asyncio.wait_for(receive(), timeout=request.body_timeout)
    except asyncio.TimeoutError:
        raise werkzeug.exceptions.RequestTimeout() from None
    # Iterating has used the body up. Put what was received back, as a complete body, so that
    # quart can parse the form from it, and request.files and request.get_data() work as usual.
    data = b"".join(chunks)
    body = request.body_class(len(data), None)
    body.append(data)
    body.set_complete()
    request.body = body


async def formdata():
    """Catch-all form data converter. Converts form data of any form (json, urlencoded, mime, etc) to a dict.

    A form (as opposed to JSON) that is larger than the MAX_FORM_CONTENT_LENGTH setting is not read.
    werkzeug's RequestEntityTooLarge is raised instead, as quart does for a body over MAX_CONTENT_LENGTH,
    and unless the caller catches it the response is a 413.

    A JSON body must be an object. For any other JSON value, as for a body that is not JSON,
    werkzeug's BadRequest is raised, and unless the caller catches it the response is a 400."""
    form_data = dict()
    form_data.update(quart.request.args.to_dict())  # query string args
    # Check the size of a form before it is parsed.
    max_size = _max_form_content_length()
    if max_size is not None and quart.request.mimetype in FORM_CONTENT_TYPES:
        content_length = quart.request.content_length
        if content_length is not None:
            # The request declares its length, so it can be refused without reading any of its body.
            # The body is not drained first: that would wait on the client for all of it.
            if content_length > max_size:
                raise _form_too_large(max_size)
        else:
            await _receive_form_body(max_size)
    xform = await quart.request.form                # POST form data
    if xform:
        form_data.update(xform.to_dict())
    if quart.request.is_json:  # JSON data from a PUT?
        xjson = await quart.request.json
        # Only an object has fields to add to the dictionary. Any other JSON value (a list, a
        # string, a number, null) is the client's mistake, as a body that is not JSON at all is.
        if not isinstance(xjson, dict):
            raise werkzeug.exceptions.BadRequest("The JSON body of this request must be an object.")
        form_data.update(xjson)
    return form_data


class FilenameConverter(werkzeug.routing.BaseConverter):
    """Simple converter that splits a filename into a basename and an extension. Only deals with filenames, not
    full paths. Thus, <filename> will match foo.txt, but not /foo/bar.baz"""

    regex = r"^[^/.]*(\.[A-Za-z0-9]+)?$"
    part_isolating = False

    def to_python(self, filename): # pylint: disable=arguments-renamed
        return os.path.splitext(filename) # superclass function uses 'value'


#
# Decorator to use a template in order to generate a webpage with some
# provided data.
#
# EXAMPLE:
#
#   @use_template(T_MAIN)
#   def main_page():
#       ...
#       data = {
#           'title': 'Main Page',
#           'count': 42,
#       }
#       return data
#
# The data dictionary will be provided to the EZT template for
# rendering the page.
#
# A handler may instead return a Response (a redirect, say); it is
# passed through untouched rather than handed to the template.
#
def use_template(template):

    # The @use_template(T_MAIN) example is actually a function call
    # to *produce* a decorator function. This is that decorator. It
    # takes a function to wrap (FUNC), and produces a wrapping function
    # that will be used during operation (WRAPPER).
    def decorator(func):

        # .wraps() copies name/etc from FUNC onto the wrapper function
        # that we return.
        @functools.wraps(func)
        async def wrapper(*args, **kw):
            # Get the data dictionary from the page endpoint.
            data = await func(*args, **kw)

            # A Response is already a page; there is nothing to render.
            if isinstance(data, werkzeug.sansio.response.Response):
                return data

            # Render that page, and return it to Quart.
            return render(template, data)

        return wrapper

    return decorator


def render(t, data):
    "Simple function to render a template into a string."
    buf = io.StringIO()
    t.generate(buf, data)
    return buf.getvalue()


class CancellableTask:
    "Wrapper for a task that does not propagate its cancellation."

    def __init__(self, coro, *, loop=None, name=None):
        "Create a task for CORO in LOOP, named NAME."

        if loop is None:
            loop = asyncio.get_event_loop()

        async def absorb_cancel():
            try:
                await coro
            except asyncio.CancelledError:
                LOGGER.debug(f'TASK CANCELLED: {self.task}')

        self.task = loop.create_task(absorb_cancel(), name=name)

    def cancel(self):
        "Cancel the task, and clean up its CancelledError exception."

        self.task.cancel()
