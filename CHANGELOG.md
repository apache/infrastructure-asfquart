Changes in 0.1.13:

 Sessions
 - Server-side sessions: set `app.sessions` to an async store (with `create`, `validate` and
   `destroy` methods, and optionally `replace` or `register`) and the cookie then carries only a
   session id. Use the new `session.awrite()`, `session.aclear()` and `session.areplace()` with such
   a store; the sync `write()` and `clear()` raise when one is configured. The interface is
   documented in `docs/session-stores.md`.
 - `session.areplace()` refuses a session object with no `uid` attribute, such as a plain dict,
   with a `TypeError`. The user's existing session is left alone.
 - Session timeouts for sessions kept in the cookie (#110):
   - Maximum session lifetime: the new `MAX_SESSION_AGE` config option (seconds) ends a session
     that many seconds after it was created, regardless of activity. It defaults to 7 days, which
     is when sessions ended before as well, because of the next point. Set it to `0` for no limit.
   - Using a session now moves its idle timeout on. The time of last use was never saved to the
     cookie, so the idle timeout ran from the login.
   - The idle timeout can be set for the whole app with the new `MAX_SESSION_IDLE` option
     (default 7 days), which `auth.require` then uses. It has an effect when it is less than
     `MAX_SESSION_AGE`.
   - `session.write()` and `awrite()` keep the creation time of the session of the user who is
     logged in, so changing a session does not extend its maximum lifetime. Pass
     `new_session=True` after authenticating a user.
 - An empty token file (`apptoken.txt`) is no longer used as the application secret, which left the
   app unable to write a session. It is treated as missing: a new secret is generated and saved.
   The application secret is now documented, in `docs/app-secret.md` (#75).

 OAuth
 - The auth endpoint accepts POST as well as GET, with a `Sec-Fetch-Site` check as light CSRF
   protection; a POST logout answers 204.
 - The `login` and `logout` redirect targets must be local paths (start with `/`, not `//`), and
   may not contain a backslash or control characters: browsers read `/\example.org` as
   `//example.org`, and the login target is sent in a `Refresh` header. A target may be at most
   2,048 characters (`generics.MAX_REDIRECT_URI_LENGTH`). Anything else is a 400 (#90, #124).
 - A pending login is tied to the browser that started it by a cookie; the callback must come from
   the same browser. The full set of callback rules is in `docs/oauth.md`.
 - `setup_oauth` takes a `callback_host` argument, to pin the host of the OAuth callback URL
   instead of taking it from the request's `Host` header. Its default is the new
   `generics.OAUTH_CALLBACK_HOST`, which is unset (#93).
 - OAuth logins that are started and never completed no longer stay in memory until a restart: they
   are removed once they have expired, and no more than `generics.DEFAULT_MAX_PENDING_LOGINS`
   (10,000) are kept, the oldest being dropped first. `setup_oauth` takes a `max_pending_logins`
   argument. A warning says how many were dropped (#99, #95).
 - The OAuth code is percent-encoded before it is sent to the OAuth provider (#88).
 - The OAuth code is sent to the provider in a `POST` body rather than the URL of a `GET`, so it
   stays out of access logs. `generics.OAUTH_URL_CALLBACK` no longer takes a `%s`. A value that
   still has one is sent as a `GET` with a warning - except the old default, which gets the `POST`.
   Redirects from the provider aren't followed (#96).
 - Responses to an OAuth endpoint URL with a code in it are sent with `Referrer-Policy: no-referrer`.
 - The original URL carried through an OAuth login redirect is percent-encoded, and a trailing `?`
   from an empty query string is dropped.
 - A session is only created when the OAuth provider's response is a JSON object with a `uid` in the
   form of an ASF user id (`generics.OAUTH_UID_RE`); anything else is a 403 (#132).
 - The exchange with the OAuth provider has a connect timeout (10s) and a total timeout (30s) next to
   the read timeout (`generics.OAUTH_TIMEOUT`). A provider that cannot be reached or is too slow is a
   403 rather than a 500 (#130).
 - The exchange with the OAuth provider states its TLS settings instead of relying on defaults:
   TLS 1.2 or later, a valid certificate, and a matching host name (#89).
 - A login that fails at the exchange with the OAuth provider is logged as a warning that says why,
   without the code or the state. How an application logs its logins is in `docs/oauth.md` (#91).
 - Logout sends a `Clear-Site-Data` header so the browser drops its cache, cookies and storage.

 Authorization, tokens and LDAP
 - `auth.require` accepts the classmethods of a `Requirements` subclass, so an app can add its own
   requirements next to the built-in ones (#41).
 - `auth.require` no longer drops its first argument when `all_of` is given as well: the two are
   combined. Anything that is not a requirement is a `TypeError` when the endpoint is defined, and
   `auth.requirements_to_iter` is deprecated (#43, #45).
 - `auth.Requirements.mfa_enabled` is now `mfa_protected`. The old name still works (#44).
 - Requirements work with any session object that has the attributes they read, not only a
   `ClientSession` - with a session store it may be something else. The attributes are listed in
   `session.SessionProtocol`, and `auth.require` raises a `TypeError` naming the attribute if a
   session is missing one (#44).
 - `basic_auth` parameter when constructing a `QuartApp` (default `True`); when off, an
   `Authorization: Basic` header is answered with 401 instead of an LDAP lookup.
 - A username for basic authentication must have the form of an ASF user id, and the password may
   not be empty; otherwise the request is a 403 and LDAP is not contacted (#128).
 - The rule for the form of an ASF user id is written in one place, `base.ASF_UID_RE`.
   `generics.OAUTH_UID_RE` and `ldap.VALID_UID_RE` are that same pattern.
 - The cache of LDAP lookups no longer keeps expired entries: they are removed whenever a lookup is
   made, and the cache holds at most `ldap.DEFAULT_LDAP_CACHE_MAX_ENTRIES` (1,000) users, the
   least recently used lookup being dropped first (#95).
 - A bearer token presented when no `token_handler` is registered is no longer printed to stdout; a
   warning without the token is logged instead (#85).
 - An `Authorization` header that does not parse no longer causes an error.

 Requests and responses
 - `utils.formdata()` refuses a form larger than the new `MAX_FORM_CONTENT_LENGTH` config option
   (default 100 KB) with a 413, before the form is parsed. The limit is separate from quart's
   `MAX_CONTENT_LENGTH`, and the lower of the two applies. A request without a `Content-Length`
   header is no longer a 500. See `docs/forms.md` (#131).
 - `use_template` passes a `Response` returned by the handler (a redirect, say) through untouched,
   instead of handing it to the template as the data dictionary.
 - Every error response from asfquart is `text/plain; charset=utf-8`.
 - Assertions became proper errors: a missing port raises `ValueError`, a failed OAuth exchange is a
   403, a non-callable `token_handler` raises `TypeError`.

 Documentation
 - New pages: the services an application depends on and what happens when they fail
   (`docs/external-services.md`, #129), and why an application runs as one process
   (`docs/one-process.md`, #160).

 Other
 - `import asfquart` now imports `asfquart.auth` as well.
 - `run()` prints an `https://` URL when a certfile is given.
 - Python 3.14 is tested and listed as supported.
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
