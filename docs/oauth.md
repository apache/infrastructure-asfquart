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

## Multi-instance limitation

OAuth state parameters are stored in a process-local dictionary in `src/asfquart/generics.py`:

```python
pending_states = {}  # keeps track of pending states and their expiry
```

In a multi-instance or load-balanced deployment, if the OAuth callback is routed to a different instance than the one that initiated the flow, the state lookup will fail because `pending_states` is not shared across processes.

See [ASVS report](https://github.com/apache/infrastructure-asfquart/issues/52)

## Pending logins, and restarting the application

A login is *pending* from the moment it starts (`/auth?login`) until the browser comes back
from the OAuth provider, or until the workflow timeout (15 minutes by default) has passed.
asfquart keeps a small record of each pending login, with its `state`, in the memory of the
process that started it. Nothing is written to disk.

### Restarting

When the application restarts, its pending logins are lost. There is no way to keep them
across a restart.

- A user who was at the OAuth provider's login page during the restart is sent back with a
  `state` that the application no longer knows, and gets `403 Invalid or expired OAuth state
  provided`. Starting the login again works.
- Users who are already logged in are not affected. Their sessions are in a cookie, or in the
  application's session store (`app.sessions`), and neither is touched by a restart, provided
  that the application keeps its secret (the `token_file` of `asfquart.construct()`) and that
  the session store, if there is one, keeps its sessions.
- The window is short: only logins that are between their start and their callback at that
  moment are lost, and that is usually a matter of seconds. Restarting when few people are
  logging in keeps it rare.

The same goes for a reload during development, and for the multi-instance case above, where
the callback reaches a process other than the one that started the login.

### Limits

Pending logins that are never completed do not accumulate:

- Records that have passed the workflow timeout are removed whenever a login starts or a
  callback arrives.
- At most 10,000 logins are pending at one time, which takes about 3 MB. When one more
  starts, the oldest is dropped to make room. If the user it belonged to then completes it,
  they get the `403` above and have to start again. A warning is logged when this happens
  (`More than 10000 OAuth logins are pending`), at most once a minute. In normal use the limit
  is never reached; it is there for a client that starts logins without end.

To use another limit, either set `asfquart.generics.DEFAULT_MAX_PENDING_LOGINS` before
calling `asfquart.construct()`, or set the endpoint up yourself:

```python
import asfquart
import asfquart.generics

app = asfquart.construct("myapp", oauth=False)
asfquart.generics.setup_oauth(app, max_pending_logins=1000)
```
