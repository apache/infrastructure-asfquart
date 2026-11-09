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

1. Rejects the redirect target with `400 Invalid redirect URI.` unless it is a local path,
   i.e. it starts with `/` and does not start with `//`.
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

Once the rules pass, the `code` is exchanged with the OAuth provider. If that exchange fails,
the response is `403 OAuth authentication failed.` Otherwise the session is created and the
browser is redirected to the recorded target (using a `Refresh` header rather than a 30x
response, so that `SameSite` session cookies are kept).

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
