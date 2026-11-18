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
     unassigned), and the line and paragraph separators U+2028 and U+2029,
   - it is no longer than 2,048 characters (`asfquart.generics.MAX_REDIRECT_URI_LENGTH`),
     because the target of a login is kept in memory until the login completes or expires.

   The same rule applies to the target of `/auth?logout=/foo`.

   A login target may not be the OAuth endpoint itself either. The browser goes to the target
   from the application's own page, so `/auth?login=/auth?logout` would let another site log a
   user out by way of a login.
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

Once the rules pass, the `code` is exchanged with the OAuth provider, in the body of a `POST`
(see [the external services page](external-services.md#token-endpoint-oauth_url_callback)).
The exchange is time
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

Any response to a URL on the OAuth endpoint with a `code` in it is sent with
`Referrer-Policy: no-referrer`, so the code isn't passed on in a `Referer` header.

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
- `callback_host` is a parameter of `setup_oauth()` that pins the host the OAuth provider sends
  the browser back to. Without it, the callback URL is built from the request's `Host` header,
  so it relies on the proxy in front of the app passing that header through unchanged
  (`ProxyPreserveHost On` for httpd). The ASF provider only accepts pre-approved callback
  URLs, which limits what a forged header can do, but setting this removes the dependency.

  Its default is `asfquart.generics.OAUTH_CALLBACK_HOST`, so an app that uses
  `asfquart.construct()` can set that instead:

  ```python
  import asfquart
  import asfquart.generics

  asfquart.generics.OAUTH_CALLBACK_HOST = "https://myapp.apache.org"
  app = asfquart.construct("myapp")
  ```

  It must be `https://` and a host name (with a port if needed), and nothing else - a bad
  value raises a `ValueError` when the app is set up. IP address literals in brackets, such as
  `https://[::1]`, aren't accepted. Users have to log in on that host, as the cookie that ties
  a login to the browser is set for the host the login started on.
- `asfquart.generics.STATE_COOKIE_SAMESITE` defaults to `"Lax"`. This is required when the
  OAuth provider is on a different site from the app, because the callback is a top-level
  navigation from the provider and browsers do not send `Strict` cookies on it. Deployments
  where the provider and the app share a site may set it to `"Strict"`.

## Requests that change state

A `GET` request ought not to change anything, because browsers, proxies and other sites make
`GET` requests freely: a link, an image, a prefetch. Three of the requests to the OAuth
endpoint do change something. Two of them have to be `GET` all the same, and one does not.

| Request | What it changes | Methods |
|---|---|---|
| `/auth?login` | Adds a pending login | `GET` and `POST` |
| `/auth?state=...&code=...` (the callback) | Completes the login and creates the session | `GET` and `POST` |
| `/auth?logout` | Ends the session, and tells the browser to clear the app's data | `POST`; `GET` unless turned off |
| `/auth` | Nothing: shows the session | `GET` and `POST` |

- **Starting a login** has to work with `GET`. The browser gets there by a redirect, from
  `enforce_login()` or from a link, and a redirect cannot be a `POST`. What it changes is
  small and bounded: one pending login, of which only so many are kept (see "Limits" below).
  A login that another site starts cannot put the user in somebody else's account, because
  it can only be completed by the browser that started it, and that user then logs in as
  themselves.
- **The callback** has to work with `GET`, because the OAuth provider sends the browser to
  it by a redirect. It is protected by the callback rules above: the `state` is random, tied
  to the browser, and can be used once.
- **Logging out** can be a `POST`, and should be.

### Logging out

Log out with a form, not with a link:

```html
<form method="post" action="/auth?logout=/">
  <button type="submit">Log out</button>
</form>
```

A `POST` to `/auth?logout` answers `204`, and one to `/auth?logout=/foo` redirects to `/foo`.

A logout is accepted from the application's own pages, and refused with a `403` when
another site asked for it: the session is left alone and the browser is not told to clear
anything. asfquart goes by the headers that browsers send with a request.

`Sec-Fetch-Site` says where the request came from:

| `Sec-Fetch-Site` | Meaning | `POST` logout | `GET` logout |
|---|---|---|---|
| `same-origin` | A page of the application itself | Accepted | Accepted, if a navigation |
| `same-site` | A page on another host of the same site | Refused, unless allowed (below) | Refused, unless allowed (below) |
| `none` | The user typed the address or used a bookmark | Refused | Accepted, if a navigation |
| `cross-site` | A page on another site: a link, a form, an image | Refused | Refused |
| not sent | An old browser, or a client that is not a browser | Accepted | Accepted |

"The same site" is wider than it sounds. It is every host that shares the application's
registered domain, so for an application at `myapp.apache.org` it is every other host under
`apache.org`. That is why it is not accepted by default.

A logout by `GET` is still accepted, because many applications have a logout link. For a
`GET`, `Sec-Fetch-Mode` and `Sec-Fetch-Dest` must also say that the request is a navigation
in a window or tab (`navigate` and `document`): the user followed a link or entered the
address. A page that fetches the address for an image, a script, a frame or with `fetch()`
is refused, even a page of the application itself.

A `GET` that a browser makes ahead of time, in case the user follows the link (a prefetch,
marked `Sec-Purpose: prefetch`), is refused as well.

Without these checks, any web page could log a user out by including the logout address as
an image. The session cookie is not sent with such a request, but the answer to a logout
carries a `Clear-Site-Data` header, which tells the browser to drop the application's
cookies, cache and storage whether the cookie was sent or not.

Two things follow for an application that keeps its logout link:

- A logout link on a page of another host no longer works, unless that host is on the same
  site and the application allows it, as described next.
- A page that is reached from another host and answers with a redirect to `/auth?logout` is
  refused as well: the browser still reports the request as coming from the other host.

#### Logging out from another host of the same site

If users have to be able to log out of the application from a link or a form on another
host of the same site, set `logout_same_site=True` when calling `setup_oauth()`. Its default
is `asfquart.generics.OAUTH_LOGOUT_SAME_SITE`, so an application that uses
`asfquart.construct()` can set that instead:

```python
import asfquart
import asfquart.generics

asfquart.generics.OAUTH_LOGOUT_SAME_SITE = True
app = asfquart.construct("myapp")
```

This applies to `POST` and to `GET` logouts alike. A `GET` must still be a navigation. Any
page on any host of the site can then send a user's window to the logout address, or submit
a form to it, so allow it only when there is such a link or form to support.

#### Turning `GET` logout off

To refuse `GET` logouts altogether, set `logout_by_get=False` when calling `setup_oauth()`.
Its default is `asfquart.generics.OAUTH_LOGOUT_BY_GET`, so an application that uses
`asfquart.construct()` can set that instead:

```python
import asfquart
import asfquart.generics

asfquart.generics.OAUTH_LOGOUT_BY_GET = False
app = asfquart.construct("myapp")
```

A `GET` (or `HEAD`) to `/auth?logout` is then a `405` with an `Allow: POST` header, and
nobody is logged out. Do this once the application's own logout is a form.

While `GET` logouts are accepted, asfquart logs one warning per process the first time one
is served, as a reminder that the application still has a logout link:

```
A logout was requested with GET. A logout changes state, so it should be a POST: use a form rather than a link, and then set asfquart.generics.OAUTH_LOGOUT_BY_GET = False. See docs/oauth.md
```

## Logging logins

asfquart does not keep an audit trail of logins. It logs a warning when the exchange with
the OAuth provider fails, so that the failure can be diagnosed (see above), but it does not
log successful logins, or who logged in from where. Which decisions to record, in what
format, and where the record goes are for the application to decide.

There are two places where an application can record them. Use the session store if the
application has one, and the hook for what the store does not see.

| | Session store | `after_request` hook |
|---|---|---|
| Needs | Server-side sessions (`app.sessions`) | Nothing |
| Successful logins | Yes | Yes |
| Logouts | Yes | No |
| Failed logins | No: they never reach the store | Yes |
| How it knows | asfquart calls it once the login has succeeded | It works it out from the request and the response |

### In the session store

An application that keeps its sessions in a store of its own (`app.sessions`) is told about
each login: asfquart calls the store's `create()` when the OAuth callback has succeeded, and
not before. It calls `destroy()` when the user logs out. Those two methods, in the store that
the application already has, are where to log:

```python
log = logging.getLogger("myapp.audit")

class Store:
    async def create(self, hsid, session_data):
        ...  # save the session, as the store does now
        log.info("login succeeded: uid=%s remote=%s", session_data.get("uid"), quart.request.remote_addr)

    async def destroy(self, hsid):
        session = ...  # find the session and delete it, as the store does now
        if session is not None:
            log.info("logout: uid=%s", session.uid)
```

This shows where the two log lines go, and nothing more. It is not a store to copy: the rest
of a store (`validate()`, and `replace()` or `register()` if the application uses
`asfquart.session.areplace()`) is left out, and is the application's own.

What to know about it:

- Nothing in the request decides whether `create()` is called, so a record of a login cannot
  be made up by sending the application a request. That is the advantage over the hook below.
- Log after the session has been saved, and log nothing that can fail. asfquart puts the
  session in the cookie only once `create()` has returned, so an error raised after saving
  leaves a session in the store that no cookie leads to. That is why the line above reads the
  user id with `session_data.get("uid")`, and not with `session_data["uid"]`.
- `create()` is called by `asfquart.session.awrite()`. The OAuth callback calls that after a
  successful login, and so does the application whenever its own code calls `awrite()`. If
  the application changes a session that way, the old session is destroyed and a new one
  created, which this logging would record as a logout and a login.
- `asfquart.session.areplace()` changes a session without calling `create()`. What it does
  call depends on the store. If the store has a `replace()` method, that is all it calls, and
  nothing is logged. If it has not, it calls `destroy()` for the old session and then
  `register()` for the new one, and this logging would record a logout that did not happen.
  A store with neither method cannot be used with `areplace()` at all.
- `destroy()` is also called for the previous session of a user who logs in again without
  logging out first. This logging then records a logout followed by a login.
- Do not log the `hsid`. It is a hash of the session id, but it is still what finds the
  session.
- `quart.request.remote_addr` is the address of the reverse proxy when there is one. The
  address of the client is then in a header such as `X-Forwarded-For`, which is only to be
  trusted in the conditions set out at the end of the next section; otherwise it is whatever
  the client sent.
- A login that fails never gets as far as the store. To record those, add the hook below.

### In an `after_request` hook

An application without a session store, where the session is kept in the cookie, has no
`create()` to log in. It can record logins with an `after_request` hook, which also sees the
logins that fail. An application that logs successful logins in its store, and adds this hook
for the failed ones, should leave the `log.info` line out of the hook, or each successful
login is recorded twice.

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
- The hook does not look at the method of the request. The OAuth endpoint takes the callback
  by `POST` as well as by `GET`, and a login that is completed by `POST` is still a login. A
  hook that recorded `GET` requests only would let one go by unrecorded.
- The hook calls `asfquart.session.read()` without naming an app, and that is deliberate.
  The OAuth endpoint writes the session for `asfquart.APP`, the application that was
  constructed last, and `read()` with no app looks in the same place. A process is expected
  to hold one application, and then there is nothing to choose. If a process does construct
  more than one, passing the hook's own `app` to `read()` would look for the session where
  the endpoint did not put it, and a login that worked would be recorded as one that failed.
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
  trail built on it can be forged. This goes for the session store above as well. See the
  security notes in
  [MDN's page on `X-Forwarded-For`](https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Forwarded-For).
- If the OAuth endpoint is not at `/auth`, compare with the path that was given to
  `asfquart.construct(..., oauth=...)` or `setup_oauth()`.

The hook has to follow the rules of the OAuth endpoint, so `tests/oauth_logging.py` runs it
against the endpoint, including the requests that must not be logged. If the endpoint changes,
those tests say that this section has to change with it. The same file has a small store
with the two log lines above in it, and checks what they record.

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
- At most 10,000 logins are pending at one time. When one more starts, the oldest is dropped
  to make room. If the user it belonged to then completes it, they get the `403` above and
  have to start again. In normal use the limit is never reached; it is there for a client
  that starts logins without end.
- The memory that 10,000 pending logins take depends on their redirect targets, which is why
  those have a maximum length: roughly 3 MB when the targets are short, as they usually are,
  and roughly 24 MB if every one is as long as it may be.
- A warning is logged when logins are dropped for want of room, at most once a minute:
  `More than 10000 OAuth logins are pending; 37 dropped since the last warning, oldest first.`
  The number is how many were dropped since the warning before. One warning with a small
  number is a burst. A warning every minute, with large numbers, is pressure that lasts, and
  may be an attack.

#### A flood of logins

Somebody who starts logins fast enough can push real ones out before their users come back
from the OAuth provider. With the default limit, and a login that takes half a minute to
complete, that needs more than 300 new logins a second, kept up for as long as the attack is
to last. A real login that is pushed out fails with the `403` above, and works when tried
again once the flood has stopped.

No limit on a table of pending logins avoids this altogether. The alternative, refusing new
logins while the table is full, would let the same flood lock everybody out for the whole
workflow timeout after it had stopped. Dropping the oldest ends the damage when the flood
ends.

asfquart does not limit how fast one client may start logins. It cannot tell clients apart
reliably: behind a reverse proxy every request comes from the proxy's address. The place to
limit the rate of requests to `/auth?login` is the reverse proxy, which does know the client.
Raising `max_pending_logins` also raises the rate that a flood has to keep up.

To use another limit, either set `asfquart.generics.DEFAULT_MAX_PENDING_LOGINS` before
calling `asfquart.construct()`, or set the endpoint up yourself:

```python
import asfquart
import asfquart.generics

app = asfquart.construct("myapp", oauth=False)
asfquart.generics.setup_oauth(app, max_pending_logins=1000)
```
