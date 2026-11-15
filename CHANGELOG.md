Changes in 0.1.14:
 - The `login` and `logout` redirect targets may not contain a backslash or control characters:
   browsers read `/\example.org` as `//example.org`, and the login target is sent in a `Refresh`
   header (#90, #124).
 - The OAuth code is percent-encoded before it is sent to the OAuth provider (#88).
 - The exchange with the OAuth provider has a connect timeout (10s) and a total timeout (30s) next to
   the read timeout (`generics.OAUTH_TIMEOUT`). A provider that cannot be reached or is too slow is a
   403 rather than a 500 (#130).
 - A session is only created when the OAuth provider's response is a JSON object with a `uid` in the
   form of an ASF user id (`generics.OAUTH_UID_RE`); anything else is a 403 (#132).
 - A bearer token presented when no `token_handler` is registered is no longer printed to stdout; a
   warning without the token is logged instead (#85).

Changes in 0.1.13:
 - `auth.require` accepts the classmethods of a `Requirements` subclass, so an app can add its own
   requirements next to the built-in ones (#41).
 - `use_template` passes a `Response` returned by the handler (a redirect, say) through untouched,
   instead of handing it to the template as the data dictionary.
 - Server-side sessions: set `app.sessions` to an async store (with `create`, `validate` and
   `destroy` methods) and the cookie then carries only a session id. Use the new `session.awrite()`,
   `session.aclear()` and `session.areplace()` with such a store; the sync `write()` and `clear()`
   raise when one is configured.
 - Maximum session lifetime: the `MAX_SESSION_AGE` config option (seconds) expires a session that
   many seconds after it was created, regardless of activity.
 - `basic_auth` parameter when constructing a `QuartApp` (default `True`); when off, an
   `Authorization: Basic` header is answered with 401 instead of an LDAP lookup.
 - The auth endpoint accepts POST as well as GET, with a `Sec-Fetch-Site` check as light CSRF
   protection; a POST logout answers 204.
 - The `login` and `logout` redirect targets must be local paths (start with `/`, not `//`);
   anything else is a 400.
 - A pending login is tied to the browser that started it by a cookie; the callback must come from
   the same browser. The full set of callback rules is in `docs/oauth.md`.
 - Logout sends a `Clear-Site-Data` header so the browser drops its cache, cookies and storage.
 - Every error response from asfquart is `text/plain; charset=utf-8`.
 - The original URL carried through an OAuth login redirect is percent-encoded, and a trailing `?`
   from an empty query string is dropped.
 - Assertions became proper errors: a missing port raises `ValueError`, a failed OAuth exchange is a
   403, a non-callable `token_handler` raises `TypeError`.
 - `import asfquart` now imports `asfquart.auth` as well.
 - `run()` prints an `https://` URL when a certfile is given.
 - An `Authorization` header that does not parse no longer causes an error.
 - Packaging moved from poetry to uv (`uv_build` backend, `uv.lock`); tests run on pytest 9 with
   pytest-asyncio 1.x; Dependabot keeps dependencies and GitHub Actions current.

Changes in 0.1.12:
 - Dependency constraints loosened from exact pins to minimums: `quart>=0.20.0,<1`, `asfpy>=0.56,<1`,
   and caret ranges for `ezt`, `easydict` and `watchfiles`. No code changes.

Changes in 0.1.11:
 - added parameter `token_file` when constructing a `QuartApp` to control if / where the app secret shall be stored.

Changes in 0.1.10:
 - OAuth redirects have switch to using the Refresh HTTP header instead of a 30x response, allowing
   samesite cookies to work with external OAuth providers when the hostname differs.

Changes in 0.1.9:
 - added the `metadata` dict to session objects where apps can store session-specific instructions
 - tightened file modes for the app secrets file. it will now fail to create if it already exists, and modes are better enforced
 - Switch from `asyncinotify` to `watchfiles` to allow for functionality on other platforms, such as macOS
 - Updated quart dependency (0.19.4 -> 0.20.0)

Changes in 0.1.8:
- Improved compatibility with Hypercorn which uses a backport of ExceptionGroup
  to function. This provides Python 3.10 compatibility.
- Adjust Python dependency allow >= 3.10, and all later 3.x versions, rather than
  just 3.10, 3.11, and 3.12.

Changes in 0.1.7:
- Fixed the PAT handler missing asyncio library import
- auth.require can now require role account as a type

Changes in 0.1.6:
- Custom token handler can now be set for sessions obtained through bearer tokens
- Session cookies are now secured by default (SameSite=Strict, HttpOnly, Secure=True)
