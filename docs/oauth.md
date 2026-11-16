# OAuth workflows

asfquart will, by default, set up an OAuth endpoint at `/auth`. Unauthenticated access
to any restricted end-point will automatically trigger a redirect to the OAuth workflow
and redirect back to the restricted end-point once successful.

You can tailor these automatic behavior to suit your need, as shown in this example:

```python
import asfquart

# Construct an app, with auto OAuth at /my_oauth
app = asfquart.construct("myapp", oauth="/my_oauth")

# Make another app, but do not enable oauth nor force login redirect (implied by no oauth)
otherapp = asfquart.construct("otherapp", oauth=False)

# Make a third app, enable oauth at /auth, but do not force logins
thirdapp = asfquart.construct("thirdapp", oauth="/auth", force_login=False)
```

## Callback consistency rules

A login is a round trip: the browser visits `/auth?login` (optionally `/auth?login=/foo`),
is redirected to the ASF OAuth provider, and comes back to `/auth?state=...&code=...`.
asfquart only accepts the callback if it is consistent with the request that started
the login. The rules are implemented in `setup_oauth()` in `src/asfquart/generics.py`.

### When the login starts

On `/auth?login` or `/auth?login=/foo`, asfquart:

1. Rejects the redirect target with `400 Invalid redirect URI.` unless it is a local path:
   - it starts with `/` and does not start with `//`,
   - it contains no backslash, because browsers read `/\example.org` as `//example.org`,
   - it contains no control characters (CR, LF, tab, NUL and so on), because the target is
     later sent in a `Refresh` header, and because browsers drop tabs and newlines from a URL.
     This covers every character in a Unicode "C" category (control, format, private use,
     unassigned), and the line and paragraph separators U+2028 and U+2029.

   The same rule applies to the target of `/auth?logout=/foo`.
2. Generates a random `state` value (`secrets.token_hex(16)`).
3. Records, in `pending_states[state]`:
   - the time the login started,
   - the redirect target (if any),
   - the SHA-256 digest of a random browser identifier.
4. Stores the browser identifier in the `asfquart-oauth-state` cookie. If the browser already
   has this cookie, the existing value is reused. The cookie is `HttpOnly`, `Secure`,
   `SameSite=Lax`, scoped to the OAuth endpoint path, and expires after the workflow timeout.
5. Redirects the browser to the OAuth provider with the `state` and the HTTPS callback URL.

### When the callback arrives

A callback must carry both `code` and `state`. It is accepted only if **all** of the
following hold:

1. **The state was issued by this application and has not been used.** The state is
   removed from `pending_states` as it is looked up, so each state can be used at most
   once. Unknown, forged, or replayed states are rejected.
2. **The callback comes from the browser that started the login.** The SHA-256 digest of the
   `asfquart-oauth-state` cookie sent with the callback must match the digest stored with the
   state. The comparison uses `hmac.compare_digest`. This prevents a login started in one
   browser from being completed in another (login CSRF).
3. **The login was completed in time.** The callback must arrive within `workflow_timeout`
   seconds of the login starting (900 seconds, i.e. 15 minutes, by default).
4. **The redirect target is the one recorded at the start.** After a successful login, the
   browser is sent to the target stored with the state. Any redirect target in the callback
   request itself is ignored, so it cannot be substituted mid-flow.

Because the state is removed before the other checks run, a callback that fails any rule
also invalidates the state; the user has to start a new login.

If rule 1, 2 or 3 fails, the response is the same in every case, so the client cannot tell
which check failed:

```
403 Invalid or expired OAuth state provided. OAuth workflows must be completed within 900 seconds.
```

Once the rules pass, the `code` is exchanged with the OAuth provider. The `code` is
percent-encoded before it is placed in the request to the provider. The exchange is time
limited (`asfquart.generics.OAUTH_TIMEOUT`): 10 seconds to connect, 15 seconds between reads,
and 30 seconds in total. The connection to the provider must use TLS 1.2 or later, and the
provider's certificate must be valid and match its host name.

The session is only created if the provider answers `200` with a JSON object whose `uid` is a
string in the form of an ASF user id (`asfquart.generics.OAUTH_UID_RE`: lower case letters,
digits, `-` and `_`, starting with a letter, at least two characters). In every other case
(the provider cannot be reached, is too slow, refuses the code, or sends something else) nothing
is stored and the response is `403 OAuth authentication failed.`

The response to the user is the same in each of those cases. What went wrong is logged as a
warning by the `asfquart.generics` logger (`OAuth code exchange failed: ...`): the kind of
error if the provider could not be reached, the status if it did not answer `200`, or which
check its response failed. The log does not have the `code`, the `state`, or the response.

After a successful exchange the browser is redirected to the recorded target (using a `Refresh`
header rather than a 30x response, so that `SameSite` session cookies are kept).

### Configuration

- `workflow_timeout` is a parameter of `asfquart.generics.setup_oauth()`. `asfquart.construct()`
  uses the default of 900 seconds; to change it, construct the app with `oauth=False` and call
  `setup_oauth()` yourself (plus `enforce_login()` if you want the automatic login redirect
  that `construct()` would otherwise set up):

  ```python
  import asfquart
  import asfquart.generics

  app = asfquart.construct("myapp", oauth=False)
  asfquart.generics.setup_oauth(app, uri="/auth", workflow_timeout=300)
  asfquart.generics.enforce_login(app, redirect_uri="/auth")
  ```
- `asfquart.generics.STATE_COOKIE_SAMESITE` defaults to `"Lax"`. This is required when the
  OAuth provider is on a different site from the app, because the callback is a top-level
  navigation from the provider and browsers do not send `Strict` cookies on it. Deployments
  where the provider and the app share a site may set it to `"Strict"`.

## Logging logins

asfquart does not keep an audit trail of logins. It logs a warning when the exchange with
the OAuth provider fails, so that the failure can be diagnosed (see above), but it does not
log successful logins, or who logged in from where. Which decisions to record, in what
format, and where the record goes are for the application to decide. An application that
needs an audit trail of logins can add one with an `after_request` hook:

```python
import logging

import asfquart
import quart

app = asfquart.construct("myapp")
log = logging.getLogger("myapp.audit")

@app.after_request
async def log_logins(response):
    request = quart.request
    args = request.args
    # Only the callback from the OAuth provider is a login decision. The OAuth endpoint treats a
    # request as the callback when it has a code and a state, neither of them empty, and is not
    # a login or logout request. Anything else must not be logged as a login: with an empty code,
    # for instance, the endpoint shows the session of a user who is logged in already.
    is_callback = (
        request.path == "/auth"
        and args.get("code") and args.get("state")
        and not args.get("login") and not args.get("logout")
    )
    if is_callback:
        # The callback answers 200 only when it has created the session. Read it back all the
        # same, and count the login as failed if it is not there.
        session = await asfquart.session.read() if response.status_code == 200 else None
        if session is not None:
            log.info("login succeeded: uid=%s remote=%s", session.uid, request.remote_addr)
        else:
            log.warning("login failed: status=%s remote=%s", response.status_code, request.remote_addr)
    return response
```

How this works:

- The callback from the OAuth provider is a request to the OAuth endpoint with a `code` and
  a `state`, neither of them empty, and without `login` or `logout`. Every other request to
  the endpoint (starting a login, logging out, showing the current session) is not a login
  decision. The test for the callback has to be this exact: anybody can send any query string,
  and `/auth?code=&state=` from a user who is logged in already answers `200` with their
  session, which a looser test would record as a login that never happened.
- The callback answers `200` when the login succeeded, and by then the session has been
  created, so the hook can read the user id from it. The hook still allows for the session
  not being there, and then records a failed login, so that it cannot raise an error of its
  own on a response that was otherwise fine. The callback answers `403` when the login was
  refused: the state was unknown, expired, already used or from another browser, or the OAuth
  provider did not accept the code. See the callback consistency rules above.
- Do not log the `code` or the `state`, and so do not log the query string of the callback.
  The `code` is a credential until it has been exchanged.
- Behind a reverse proxy, `request.remote_addr` is the address of the proxy. Use the header
  that your proxy sets (`X-Forwarded-For`, say) if you want the address of the client, but
  only if the proxy overwrites that header and the application cannot be reached except
  through the proxy. Otherwise the header is whatever the client chose to send, and an audit
  trail built on it can be forged. See the security notes in
  [MDN's page on `X-Forwarded-For`](https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Forwarded-For).
- If the OAuth endpoint is not at `/auth`, compare with the path that was given to
  `asfquart.construct(..., oauth=...)` or `setup_oauth()`.

The hook has to follow the rules of the OAuth endpoint, so `tests/oauth_logging.py` runs it
against the endpoint, including the requests that must not be logged. If the endpoint changes,
those tests say that this section has to change with it.

## Multi-instance limitation

OAuth state parameters are stored in a process-local dictionary in `src/asfquart/generics.py`:

```python
pending_states = {}  # keeps track of pending states and their expiry
```

In a multi-instance or load-balanced deployment, if the OAuth callback is routed to a different instance than the one that initiated the flow, the state lookup will fail because `pending_states` is not shared across processes.

See [ASVS report](https://github.com/apache/infrastructure-asfquart/issues/52)
