#!/usr/bin/env python3
"""Miscellaneous helpers for ASFQuart"""

import quart
import werkzeug.routing

DEFAULT_MAX_CONTENT_LENGTH = 102400

async def formdata():
    """Catch-all form data converter. Converts form data of any form (json, urlencoded, mime, etc) to a dict"""
    form_data = dict()
    form_data.update(quart.request.args.to_dict())  # query string args
    xform = await quart.request.form                # POST form data
    # Pre-parse check for form data size
    if quart.request.content_type and any(
            x in quart.request.content_type
            for x in (
                    "multipart/form-data",
                    "application/x-www-form-urlencoded",
                    "application/x-url-encoded",
            )
    ):
        # If the content is too large for us to handle, we need to silently ignore every chunk, so we can return with a
        # cleared buffer, lest bad things happen.
        max_size = quart.current_app.config.get("MAX_CONTENT_LENGTH", DEFAULT_MAX_CONTENT_LENGTH)
        if quart.request.content_length > max_size:
            async for _data in quart.request.body:
                pass
            return quart.Response(
                status=413,
                response=f"Request content length ({quart.request.content_length} bytes) is larger than what is permitted for form data ({max_size} bytes)!",
            )
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

    def to_python(self, filename):
        extension = ""
        # If foo.bar, split into base and ext. Otherwise, keep filename as full string (even for .htaccess etc)
        if "." in filename[1:]:
            filename, extension = filename.split(".", maxsplit=1)
        return filename, extension
