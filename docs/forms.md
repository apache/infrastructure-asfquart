# Form data

`asfquart.utils.formdata()` collects the data sent with a request into one dictionary: the
query string arguments, the fields of a form (`application/x-www-form-urlencoded` or
`multipart/form-data`), and a JSON object.

```python
import asfquart
import asfquart.utils
import quart

APP = asfquart.APP

@APP.route("/submit", methods=["POST"])
async def submit():
    data = await asfquart.utils.formdata()
    if isinstance(data, quart.Response):
        return data  # the form was too large, see below
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

When a form is larger than the limit, `formdata()` does not parse it. It returns a `413`
response in place of the dictionary, which the endpoint should return as it is.

- If the request has a `Content-Length` header, the form is refused on that header, before
  its body is read.
- If it has none (chunked transfer encoding), the body has to be received before it can be
  measured. quart stops receiving at `MAX_CONTENT_LENGTH`, so that setting is what bounds
  the memory used by such a request.

The limit counts the whole body of the request. For a `multipart/form-data` request that
includes any files sent with the form.
