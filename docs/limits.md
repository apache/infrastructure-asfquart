# Limits and timeouts

This page collects the size, count and time limits ASFQuart enforces, with their defaults and how to
change them. See also [input validation rules](input-validation.md).

| Limit | Default | Configured by | When exceeded |
|-------|---------|---------------|---------------|
| Form request body size | 102400 bytes (100 KiB) | `MAX_CONTENT_LENGTH` in the Quart app config | `413` response |
| OAuth login workflow time | 900 seconds (15 minutes) | `workflow_timeout` argument to `asfquart.generics.setup_oauth()` | `403`, the login must be restarted |
| Session idle time | 7 days | `expiry_time` argument to `asfquart.session.read()` | the session is discarded and `read()` returns `None` |
| Session lifetime | unlimited (`0`) | `MAX_SESSION_AGE` in `config.yaml`, in seconds | the session is discarded |

## Form request body size

`asfquart.utils.formdata()` compares the `Content-Length` of `multipart/form-data` and URL-encoded
requests with the `MAX_CONTENT_LENGTH` setting of the Quart app, which defaults to 102400 bytes. If the
request is larger, its body is discarded unread and a `413` response is returned. JSON bodies are not
checked by this function.

```python
app = asfquart.construct("name_of_app")
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # allow up to 1 MiB
```

## OAuth login workflow time

A login started at `/auth?login` must be completed at the OAuth provider and returned to the callback
within `workflow_timeout` seconds. The same value is used as the lifetime of the browser state cookie.
Longer-lived logins are refused with a `403` and the user has to start again. The timeout is set by
passing `workflow_timeout` to `asfquart.generics.setup_oauth()`; the endpoint that `construct()` sets up
for you uses the default.

## Session idle time and lifetime

For cookie sessions, `asfquart.session.read()` discards a session that has not been used for
`expiry_time` seconds (7 days by default). Every successful read counts as use and refreshes the
session's last-used time.

Independently of use, `MAX_SESSION_AGE` caps the total lifetime of a session, measured from when it was
created. It is disabled when unset or `0`:

```yaml
# config.yaml
MAX_SESSION_AGE: 86400  # force a new login after 24 hours
```
