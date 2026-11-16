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
DEFAULT_MAX_CONTENT_LENGTH = DEFAULT_MAX_FORM_CONTENT_LENGTH  # the former name of this default

FORM_CONTENT_TYPES = (
    "multipart/form-data",
    "application/x-www-form-urlencoded",
    "application/x-url-encoded",
)


def _max_form_content_length():
    """The largest form that formdata() will read, in bytes, or None if there is no limit.

    Forms have a limit of their own, the MAX_FORM_CONTENT_LENGTH setting, so that it can be small
    without also limiting other request bodies such as uploads. Quart's MAX_CONTENT_LENGTH applies
    to every request body, forms included, so the lower of the two is the limit for a form."""
    config = quart.current_app.config
    limits = (
        config.get("MAX_FORM_CONTENT_LENGTH", DEFAULT_MAX_FORM_CONTENT_LENGTH),
        config.get("MAX_CONTENT_LENGTH"),
    )
    limits = [limit for limit in limits if limit is not None]
    return min(limits) if limits else None


def _form_too_large(size: int, max_size: int) -> quart.Response:
    return quart.Response(
        status=413,
        response=f"Request content length ({size} bytes) is larger than what is permitted for form data ({max_size} bytes)!",
        content_type="text/plain; charset=utf-8"
    )


async def formdata():
    """Catch-all form data converter. Converts form data of any form (json, urlencoded, mime, etc) to a dict.

    A form (as opposed to JSON) that is larger than the MAX_FORM_CONTENT_LENGTH setting is not read:
    the return value is then a 413 response, which the caller should return as it is."""
    form_data = dict()
    form_data.update(quart.request.args.to_dict())  # query string args
    # Pre-parse check for form data size. This must come before the form is parsed.
    content_type = quart.request.content_type
    max_size = _max_form_content_length()
    if max_size is not None and content_type and any(x in content_type for x in FORM_CONTENT_TYPES):
        content_length = quart.request.content_length
        if content_length is not None:
            if content_length > max_size:
                # If the content is too large for us to handle, we need to silently ignore every chunk, so we can
                # return with a cleared buffer, lest bad things happen. Quart stops us reading a body that is over
                # its own limit.
                try:
                    async for _data in quart.request.body:
                        pass
                except werkzeug.exceptions.RequestEntityTooLarge:
                    pass
                return _form_too_large(content_length, max_size)
        else:
            # The request does not declare its length (chunked transfer encoding), so the body has to be
            # received before it can be measured. Quart stops receiving at MAX_CONTENT_LENGTH, and raises
            # RequestEntityTooLarge, which becomes a 413. The body is kept, so the form can still be parsed.
            body_length = len(await quart.request.get_data())
            if body_length > max_size:
                return _form_too_large(body_length, max_size)
    xform = await quart.request.form                # POST form data
    if xform:
        form_data.update(xform.to_dict())
    if quart.request.is_json:  # JSON data from a PUT?
        xjson = await quart.request.json
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
