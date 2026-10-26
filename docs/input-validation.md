# Input validation rules

This page lists the checks ASFQuart applies to input before using it. Anything not listed here is
left to the application.

## Login and logout redirects

The `/auth?login=<uri>` and `/auth?logout=<uri>` endpoints (see [OAuth](oauth.md)) only accept
local, absolute-path redirects:

- the value must start with a single `/`
- values starting with `//` (protocol-relative URLs), or anything else, such as `https://...`,
  `javascript:...` or `data:...`, are refused with `400 Invalid redirect URI.`

A bare `?login` or `?logout`, with no value, is always accepted.

## OAuth callback

The callback is only processed when both the `code` and `state` query parameters are present, and the
state must pass all of the following, otherwise the request is refused with `403`:

- the state must have been issued by this app and not been used before; each state can be used once
- it must be presented by the same browser that started the login, matched through the state cookie
- the login must be completed within the workflow timeout (see [limits](limits.md))

## Cross-site requests

A `POST` to the auth endpoint is refused with `403` if the `Sec-Fetch-Site` header is present and is
not `same-origin` or `same-site`. Requests without the header are allowed.

## Form data

`asfquart.utils.formdata()` merges query string arguments, form fields and a JSON body into one
dict. Form-style request bodies (`multipart/form-data` and URL-encoded) are checked against a
maximum size before they are read, see [limits](limits.md).

## The `filename` URL converter

The `<filename:...>` route converter matches a single path segment, optionally followed by one
extension. The regular expression is `^[^/.]*(\.[A-Za-z0-9]+)?$`, so:

- the name may not contain `/` or `.`
- the extension, if present, may only contain ASCII letters and digits

The converted value is a `(name, extension)` tuple, as returned by `os.path.splitext()`. For example,
`foo.txt` matches, but `foo.tar.gz` and `bar/baz.txt` do not.

## Sessions

When a session store is configured, a session cookie is only used if it holds a non-empty string
`sid` that the store recognizes. Otherwise the cookie entry is removed and no session is returned.
