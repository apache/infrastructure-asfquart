# Form data

`asfquart.utils.formdata()` collects the data sent with a request into one dictionary: the
query string arguments, the fields of a form (`application/x-www-form-urlencoded` or
`multipart/form-data`), and a JSON object.

```python
import asfquart
import asfquart.utils

APP = asfquart.APP

@APP.route("/submit", methods=["POST"])
async def submit():
    data = await asfquart.utils.formdata()
    return {"received": sorted(data)}
```

## Size limit

Forms have a size limit of their own, so that it can be small without also limiting other
request bodies, such as file uploads that the application reads itself.

| Setting | Applies to | Default |
|---|---|---|
| `MAX_FORM_CONTENT_LENGTH` | Forms read by `formdata()` | 102400 bytes (100 KB) |
| `MAX_CONTENT_LENGTH` (quart) | Every request body, forms included | 16 MB |

A form is also a request body, so the lower of the two is the limit for a form.

```python
app = asfquart.construct("myapp")
app.config["MAX_FORM_CONTENT_LENGTH"] = 1024 * 1024  # allow forms of up to 1 MB
```

Set `MAX_FORM_CONTENT_LENGTH` to `None` to have no limit for forms other than
`MAX_CONTENT_LENGTH`.

The setting is a number of bytes. A string that holds a number, as a value read from the
environment is, is accepted too.

When a form is larger than the limit, `formdata()` does not parse it. It raises werkzeug's
`RequestEntityTooLarge`, the exception that quart raises for a body over `MAX_CONTENT_LENGTH`.
An endpoint does not need to do anything about it: left alone, it becomes a `413` response.

- If the request has a `Content-Length` header, the form is refused on that header, without
  any of its body being read.
- If it has none (chunked transfer encoding), the body is counted as it arrives, and the form
  is refused as soon as it passes the limit, without the rest being received. A client that
  stops sending is given up on after quart's `BODY_TIMEOUT` (60 seconds by default), with a
  `408`.

A request is a form if its content type is one that quart parses as a form:
`application/x-www-form-urlencoded`, `multipart/form-data` or `application/x-url-encoded`,
in any letter case.

The limit counts the whole body of the request. For a `multipart/form-data` request that
includes any files sent with the form.
