# Input validation rules

asfquart checks some of what comes into an application, and leaves the rest to the
application. This page lists the checks asfquart makes: what is checked, the rule, what
happens when the rule is not met, and where in the source the rule is written. It ends with
what asfquart does *not* check.

| Input | Comes from | Section |
|---|---|---|
| Requests to the OAuth endpoint | The browser | [The OAuth endpoint](#the-oauth-endpoint) |
| The OAuth provider's answer | The OAuth provider | [The OAuth provider's response](#the-oauth-providers-response) |
| The `Authorization` header | The client | [The Authorization header](#the-authorization-header) |
| The session cookie | The browser | [The session cookie](#the-session-cookie) |
| Forms | The client | [Forms](#forms) |
| File names in a URL | The client | [File names in a URL](#file-names-in-a-url) |
| Settings and arguments | The application | [What the application supplies](#what-the-application-supplies) |

## The form of an ASF user id

An ASF user id is two or more characters: a lower case letter, followed by lower case
letters, digits, `-` or `_`. The whole value must match.

The rule is written once, as `asfquart.base.ASF_UID_RE`. `asfquart.generics.OAUTH_UID_RE` and
`asfquart.ldap.VALID_UID_RE` are the same pattern under the names of the two places it is
applied: the `uid` in the OAuth provider's response, and the username of HTTP Basic
authentication.

| Value | A user id? |
|---|---|
| `humbedooh` | Yes |
| `ab` | Yes |
| `a-b_c9` | Yes |
| `a` | No: one character |
| `9lives` | No: starts with a digit |
| `-ab` | No: starts with `-` |
| `Humbedooh` | No: upper case |
| `ab.cd` | No: `.` is not allowed |
| `ab cd` | No: a space is not allowed |
| `uid=ab,ou=people` | No |

## The OAuth endpoint

These are the checks on requests to the endpoint that `setup_oauth()` adds (`/auth` by
default). They are in `asfquart/generics.py`. The reasons for the callback rules are in
[Setting up OAuth](oauth.md#callback-consistency-rules).

| What | Rule | If not met |
|---|---|---|
| A `POST` request | `Sec-Fetch-Site` is absent, `same-origin` or `same-site` | `403`, "CSRF Protection" |
| A logout, by `POST` or `GET` | `Sec-Fetch-Site` is absent or `same-origin`; `same-site` as well if `logout_same_site` is set | `403`, "CSRF Protection" |
| A `GET` logout, when `logout_by_get` is off | Refused | `405`, "Log out with a POST request." |
| A `GET` logout | A navigation in a window or tab: see below | `403`, "CSRF Protection" |
| A `GET` logout | Not a prefetch: no `Sec-Purpose` that starts with `prefetch`, and no `Purpose` or `X-Moz` of `prefetch` | `403`, "Not prefetched" |
| The target of `?login=` or `?logout=` | A local path: see below | `400`, "Invalid redirect URI." |
| The target of `?login=` | Not the OAuth endpoint itself: see below | `400`, "Invalid redirect URI." |
| A callback | Has a `code` and a `state`, neither of them empty | Not treated as a callback: the session is shown, or a `404` |
| The `state` of a callback | A login that this application started, that has not been completed, and that has not expired (`workflow_timeout`, 900 seconds by default) | `403`, "Invalid or expired OAuth state provided." |
| The browser of a callback | Sends the `__Host-asfquart-oauth-state` cookie that was set when this login started | `403`, the same message |
| The `code` of a callback | Not checked by asfquart: it is passed to the OAuth provider, which accepts it or not | `403`, "OAuth authentication failed." |

A `state` can be used once. It is given up when it is looked at, so a callback that fails
any later check cannot be tried again with the same `state`.

A `GET` logout that comes with a `Sec-Fetch-Site` is a navigation when `Sec-Fetch-Mode` is
`navigate` and `Sec-Fetch-Dest` is `document`. `Sec-Fetch-Site` may then be `none` as well.

A logout that is refused leaves the session alone. The reasons for the logout rules are in
[Setting up OAuth](oauth.md#logging-out).

A logout that is accepted, with a target that is refused, still logs the user out. The `400`
is for the redirect, which is not made.

### Redirect targets

The value of `?login=` is where the browser is sent after a login, and the value of
`?logout=` where it is sent after a logout. Both must be a path on the application's own
site (`_is_local_redirect()`):

- at most 2,048 characters (`asfquart.generics.MAX_REDIRECT_URI_LENGTH`),
- starting with `/`, and not with `//`, which a browser reads as another host,
- with no backslash anywhere, because browsers read `\` as `/`,
- with no control characters. That is every character in a Unicode "C" category (control,
  format, surrogate, private use and unassigned), and the line and paragraph separators
  U+2028 and U+2029. A carriage return or line feed would split a header, and browsers drop
  tabs and newlines from an address before reading it.

The value is checked after the query string has been decoded, so `%2F%2Fexample.org` is
refused as `//example.org` is.

A login target may also not be the OAuth endpoint itself (`_is_oauth_endpoint()`), as a
browser would resolve it: `/x/../auth` and `/%61uth` are refused too. The reason is in
[Setting up OAuth](oauth.md#when-the-login-starts).

| Target | Accepted? |
|---|---|
| `/` | Yes |
| `/dashboard` | Yes |
| `/a/b?c=d&e=f#g` | Yes |
| `/a//b` | Yes: only a leading `//` is another host |
| `dashboard` | No: does not start with `/` |
| `//example.org` | No: another host |
| `https://example.org/` | No: does not start with `/` |
| `javascript:alert(1)` | No: does not start with `/` |
| `/\example.org` | No: a backslash |
| `/a\b` | No: a backslash |

## The OAuth provider's response

When a callback has passed the checks above, asfquart exchanges the `code` with the OAuth
provider, and creates a session from the answer only if the answer identifies a user
(`_oauth_data_problem()` in `asfquart/generics.py`):

| What | Rule |
|---|---|
| The exchange | Completes within the time limits, over TLS 1.2 or later, with a valid certificate for the provider's host name |
| The status | `200`. A redirect is not followed |
| The body | JSON, and a JSON object |
| `uid` | Present, a string, and in the form of an ASF user id |
| `origin_uri`, if present | A string, and the callback address of this login: the same scheme, host, port and path, and the same `state`. No user name in it |

If any of these is not met the login fails with a `403`, "OAuth authentication failed.", no
session is created, and a warning in the log says which rule it was. The warning does not
contain the `code`, the `state` or the response.

`origin_uri` is the address the provider was asked to send the browser back to, so this
refuses a response that belongs to a login at another application, or to another login at
this one. A response without it is accepted, and that is logged once. See
[Setting up OAuth](oauth.md#the-response-must-be-for-this-login).

The other fields of the response (`fullname`, `email`, `isMember`, `pmcs` and so on) are not
checked. They are stored in the session as they were received.

## The Authorization header

A request without a session may identify its user with an `Authorization` header. These
checks are in `asfquart/session.py` (`read()`) and `asfquart/ldap.py` (`LDAPClient`).

The header is only looked at when the browser's cookie has no session for this application.
A request that carries both a session cookie and an `Authorization` header is handled by its
cookie, even if the session in it has ended.

| What | Rule | If not met |
|---|---|---|
| The header | Can be parsed as an `Authorization` header | Ignored: the request has no session |
| The scheme | `Basic` or `Bearer` | `501`, "Not implemented yet" |
| `Basic`, unless the application was constructed with `basic_auth=True` | Refused | `401`, "Basic authentication is not enabled" |
| The `Basic` username | In the form of an ASF user id | `403`, "Invalid credentials provided" |
| The `Basic` password | Not empty | `403`, "Invalid credentials provided" |
| The `Basic` credentials | Accepted by LDAP | `403`, "Invalid credentials provided" |
| A `Bearer` token | Present, and not empty | No session; the application's `token_handler` is not called |
| A `Bearer` token that is present | Not checked by asfquart: it is passed to the application's `token_handler` | No session if the handler returns nothing, or if there is no handler |

- The username and password are checked before LDAP is contacted. The username goes into an
  LDAP distinguished name, and a bind with a name and an empty password is an anonymous bind
  that many servers accept, so neither may reach LDAP unchecked.
- If LDAP cannot be reached, the answer is a `500`, not a `403`.
- HTTP Basic authentication is off by default, and needs the LDAP libraries
  (`asfquart[aioldap]`). An application that sets `app.basic_auth = True` itself, without
  them, answers a `Basic` header with a `500`, "Basic authentication is not available". See
  [HTTP Basic authentication](sessions.md#http-basic-authentication).
- A bearer token is never written to the log.

## The session cookie

The session cookie is signed with the [application secret](app-secret.md). That signature is
checked by quart, not by asfquart: a cookie that has been altered, or that was signed with
another secret, is treated as no cookie at all.

What asfquart then checks depends on where sessions are kept. Both sets of checks are in
`read()` in `asfquart/session.py`.

**Sessions kept in the cookie** (the default):

| What | Rule | If not met |
|---|---|---|
| The application's entry in the cookie | A dictionary | No session |
| `uts`, the time the session was last used | A number, and not longer ago than the idle limit | No session, and the entry is removed |
| `cts`, the time the session was created | A number, and not longer ago than `MAX_SESSION_AGE` | No session, and the entry is removed |

A timestamp that is not a number (a string, `true`, or missing) is treated as missing. A
session with no `uts` has ended, if there is an idle limit. A session with no `cts` was
written by a version of asfquart that did not record one; it is kept, and its clock starts
then. The limits themselves are described in [Session handling](sessions.md).

**Sessions kept in a store** (`app.sessions`):

| What | Rule | If not met |
|---|---|---|
| The application's entry in the cookie | A dictionary with a `sid` that is a string and not empty | No session, and the entry is removed |
| The session | The store's `validate()` returns it | No session, and the entry is removed |

Everything else about a stored session, its time limits included, is the store's to check.
See [Session stores](session-stores.md).

The contents of a session (`uid`, `is_member`, `committees` and the rest) are not checked
when it is read. They were put there by the application or by asfquart, and the signature
says that they have not been changed since.

## Forms

`asfquart.utils.formdata()` reads a form, and refuses one that is too large before it is
parsed. The check is in `asfquart/utils.py`, and is described in
[Form data and its size limit](forms.md).

| What | Rule | If not met |
|---|---|---|
| A request body whose content type is one of `asfquart.utils.FORM_CONTENT_TYPES` | At most `MAX_FORM_CONTENT_LENGTH` bytes (102,400 by default), and at most quart's `MAX_CONTENT_LENGTH` | `413` |
| A form sent without a `Content-Length` | Arrives within quart's body timeout | `408` |
| A JSON body | JSON, and a JSON object: not a list, a string, a number, `true`, `false` or `null` | `400` |

The size limit applies to forms. A JSON body is limited only by quart's `MAX_CONTENT_LENGTH`.

## File names in a URL

Routes can use the `filename` converter (`asfquart.utils.FilenameConverter`), which matches
one path segment and splits it into a name and an extension. It matches a name with no `/`
and no `.` in it, optionally followed by one `.` and an extension of letters and digits.
A URL that does not match is not routed to the endpoint, which is a `404` unless another
route matches.

| Value | Matches? |
|---|---|
| `report` | Yes |
| `report.txt` | Yes |
| `.txt` | Yes: an empty name |
| `report.tar.gz` | No: two dots |
| `dir/report.txt` | No: a `/` |
| `../report.txt` | No |
| `report.t-x` | No: the extension is letters and digits only |

## What the application supplies

These are checked when the application starts, or when an endpoint is defined, and raise an
exception there, so that a mistake does not wait for a request to show itself.

| What | Rule | If not met | Where |
|---|---|---|---|
| `callback_host` of `setup_oauth()`, or `generics.OAUTH_CALLBACK_HOST` | `https://`, a host name, optionally a port, optionally a final `/`, and nothing else | `ValueError` | `generics.py` |
| `max_pending_logins` of `setup_oauth()` | At least 1 | `ValueError` | `generics.py` |
| `basic_auth=True` of `construct()` | The LDAP libraries are installed | `RuntimeError` | `base.py` |
| Arguments of `@asfquart.auth.require` | Each is a method of `asfquart.auth.Requirements` or of a subclass of it | `TypeError` | `auth.py` |
| A bare `@asfquart.auth.require` | Decorates an `async` function | `TypeError` | `auth.py` |
| `port` of `runx()` | Given | `ValueError` | `base.py` |
| The token file | Not empty | A new secret is generated and written to it | `base.py` |

Some can only be checked when they are used:

| What | Rule | If not met | Where |
|---|---|---|---|
| `generics.OAUTH_CALLBACK_HOST`, if set after the application was set up | As above | `ValueError` when a login starts, so a `500` | `generics.py` |
| `MAX_FORM_CONTENT_LENGTH` and `MAX_CONTENT_LENGTH` | A number, or `None` | `ValueError` when a form is read | `utils.py` |
| `app.token_handler` | Callable | `TypeError` when a bearer token is presented | `session.py` |
| The session object given to `session.areplace()` | Has a `uid` attribute | `TypeError`; the user's session is left as it was | `session.py` |
| The session that `@asfquart.auth.require` tests | Has the attribute that each requirement reads | `TypeError`; the endpoint is not run | `auth.py` |
| The value a requirement reads, such as `is_member` | Is `True`, and not merely something true | The requirement is not met | `auth.py` |

A callback host is matched against a pattern as a whole, not parsed:

| Value | Accepted? |
|---|---|
| `https://myapp.apache.org` | Yes |
| `https://myapp.apache.org/` | Yes |
| `https://localhost.apache.org:8080` | Yes |
| `http://myapp.apache.org` | No: not `https` |
| `myapp.apache.org` | No: no scheme |
| `https://myapp.apache.org/app` | No: a path |
| `https://user:pw@myapp.apache.org` | No: a user name |
| `https://[::1]` | No: an address literal |

## The values

The patterns and limits named on this page, and their values. `tests/input_validation.py`
compares this table, and the tables of examples above, with the code.

| Name | Value |
|---|---|
| `asfquart.base.ASF_UID_RE` | `[a-z][a-z0-9_-]{1,}` |
| `asfquart.generics.OAUTH_UID_RE` | `[a-z][a-z0-9_-]{1,}` |
| `asfquart.ldap.VALID_UID_RE` | `[a-z][a-z0-9_-]{1,}` |
| `asfquart.generics.MAX_REDIRECT_URI_LENGTH` | `2048` |
| `asfquart.generics.MAX_CALLBACK_HOST_LENGTH` | `268` |
| `asfquart.generics._CALLBACK_HOST_RE` | `https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?` |
| `asfquart.generics.STATE_COOKIE_NAME` | `__Host-asfquart-oauth-state` |
| `asfquart.generics.DEFAULT_MAX_PENDING_LOGINS` | `10000` |
| `asfquart.utils.DEFAULT_MAX_FORM_CONTENT_LENGTH` | `102400` |
| `asfquart.utils.FORM_CONTENT_TYPES` | `multipart/form-data, application/x-www-form-urlencoded, application/x-url-encoded` |
| `asfquart.utils.FilenameConverter.regex` | `^[^/.]*(\.[A-Za-z0-9]+)?$` |
| `asfquart.session.DEFAULT_MAX_SESSION_AGE` | `604800` |
| `asfquart.session.DEFAULT_MAX_SESSION_IDLE` | `604800` |

## What asfquart does not check

asfquart checks what it uses itself. What it hands to the application is the application's
to check:

- **The contents of a form.** `formdata()` limits the size of a form, and returns its fields
  as they were sent: any names, any values, all of them strings. Values from the query
  string, the form and a JSON body are merged into one dictionary, the later replacing the
  earlier, so a field in the body replaces one of the same name in the query string.
- **The contents of a JSON object.** `formdata()` checks that a JSON body is an object, and
  returns its fields as they were sent: any names, and values of any JSON type, nested to
  any depth.
- **Query string parameters** of the application's own endpoints, and **parts of the URL**
  other than the `filename` converter above.
- **Request headers**, other than `Authorization` and, on the OAuth endpoint, the
  `Sec-Fetch-*` and prefetch headers in the table above. In particular asfquart does not
  validate `Host`, beyond its length when a login starts: unless `callback_host` is set, the
  OAuth callback address is built from it, so the proxy in front of the application has to
  pass it through unchanged, and has to refuse the ones that are not the application's own.
  See [Setting up OAuth](oauth.md).
- **Uploaded files.**
- **The fields of a session other than `uid`.** What the OAuth provider says about a user
  is stored as received, and what the application passes to `session.write()` is stored as
  given. `uid` is checked when it comes from the OAuth provider or from HTTP Basic
  authentication; a session that the application writes itself, or that its `token_handler`
  returns, may have any `uid` or none.
- **The configuration file** (`config.yaml`). It is parsed as YAML, and what is in it is not
  checked.
- **Data passed to a template.** See [Simplified EZT templating](templates.md).
