# Session handling

OAuth user sessions can be accessed through the `asfquart.session` component, and are encrypted
to ensure authenticity.

The login and logout flow is automatically handled by asfquart, unless explicitly told not to,
and sessions can be accessed and modified as needed:

```python
@asfquart.auth.require  # Implicitly require a valid (non-empty) session
async def endpoint_with_session():
    session = await asfquart.session.read()  # Read user session dict
    session["foobar"] = 42
    asfquart.session.write(session)  # Store our changes in the user session
```

## Session timeouts

A session ends, and the user has to log in again, when either of two limits is passed:

| Limit | Option in `config.yaml` | Default | Counted from |
|---|---|---|---|
| Idle timeout | `MAX_SESSION_IDLE` | 7 days | When the session was last used |
| Maximum lifetime | `MAX_SESSION_AGE` | 7 days | When the user logged in |

Both are in seconds, and `0` means no limit:

```yaml
MAX_SESSION_IDLE: 3600      # log out after an hour without a request
MAX_SESSION_AGE: 86400      # and a day after logging in, in any case
```

How the two work together:

- Every request that reads the session counts as using it, and moves the idle timeout on. So
  that the cookie is not sent again with every response, the time of last use is saved at most
  once a minute (or once every tenth of the idle timeout, if that is less).
- The maximum lifetime is not moved on by anything except logging in again. Changing the
  session with `asfquart.session.write()` keeps the time it was created.
- Logging in starts a new session, with both limits counted afresh. The OAuth endpoint does
  this. An application that logs users in by some means of its own should pass
  `new_session=True` to `write()`; without it, a write for the user who is already logged in
  is taken as a change to their session.
- The idle timeout only has an effect if it is shorter than the maximum lifetime. The
  defaults are the same, 7 days, so by default it has none: every session ends 7 days after
  the user logged in, whether it was used or not. To log out users who have gone away sooner
  than that, set `MAX_SESSION_IDLE` to less than `MAX_SESSION_AGE`.

A single call can use an idle timeout of its own, in place of `MAX_SESSION_IDLE`, by passing
the `expiry_time` argument to `read()`. An endpoint that needs a recently used session can ask
for one:

```python
# Require a session that has been accessed in the past 24 hours.
session = await asfquart.session.read(expiry_time=24 * 3600)
assert session, "No session found or session expired"  # If too old or not found, read() returns None
```

Since the time of last use is saved at most once a minute, such a limit is accurate to within
a minute.

### With a session store

These limits are applied by asfquart to sessions that are kept in the cookie. An application
that keeps its sessions in a store of its own (`app.sessions`) applies its own: asfquart takes
what the store's `validate()` returns as the session, and `MAX_SESSION_IDLE`,
`MAX_SESSION_AGE` and the `expiry_time` argument are not used. The store should enforce both
an idle timeout and a maximum lifetime, with the idle timeout the shorter of the two.

### NIST SP 800-63B

The defaults are chosen for Authentication Assurance Level 1 (AAL1) of
[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/aal/), which is the level that
asfquart applications are run at:

- AAL1 requires a definite overall timeout, and recommends that it be no more than 30 days.
  The default `MAX_SESSION_AGE` is 7 days, well within that.
- AAL1 does not require an inactivity timeout, and by default there is none in effect: the
  default `MAX_SESSION_IDLE` is the same 7 days as the overall timeout.
- Logging in again resets both timeouts, as the guidelines require.

An application that sets `MAX_SESSION_AGE` to `0`, or to more than 30 days, departs from the
AAL1 recommendation, and should record why.

AAL2 asks for more: an overall timeout of no more than 24 hours, an inactivity timeout of no
more than an hour, and two authentication factors. asfquart does not claim AAL2. Shorter
timeouts can be configured as above, but the second factor is a matter for the ASF's OAuth
provider and not for asfquart.

## Cookie names

asfquart's two cookies have names that begin with `__Host-`:

| Cookie | Name | Set where |
|---|---|---|
| The session | `__Host-session` | `SESSION_COOKIE_NAME` in the app's config, by `asfquart.construct()` |
| The browser's part in a login that is under way | `__Host-asfquart-oauth-state` | `asfquart.generics.STATE_COOKIE_NAME` |

The prefix is an instruction to the browser. A browser accepts a cookie whose name begins
with `__Host-` only if the cookie is `Secure`, has `Path=/`, has no `Domain`, and came over
HTTPS. A cookie with such a name was therefore set by this very host, and by nothing else.

That matters because the other attributes of a cookie (`Secure`, `HttpOnly`, `SameSite`)
say when it is sent and who may read it, and not who may set it. Any host can set a cookie
for the whole site that it is part of, by giving it a `Domain`: a page on any `apache.org`
host can give the browser a cookie that is then sent to every other `apache.org` host.
Without the prefix, such a page could hand a visitor's browser a session cookie of its
author's own, so that the visitor uses the application as somebody else without knowing,
or its own cookie for a login, to complete a login in the visitor's browser. With the
prefix, the browser does not accept such a cookie.

What follows from the prefix:

- **The session cookie cannot be shared between hosts.** Do not set `SESSION_COOKIE_DOMAIN`
  or `SESSION_COOKIE_PATH`: a browser refuses a `__Host-` cookie that has a domain, or a path
  other than `/`, and nobody would stay logged in.
- **The session cookie is for the whole host, and not for a path on it.** An application that
  is served from a path (`APPLICATION_ROOT`, `/myapp` say) cannot keep its cookie to that
  path under this name. Applications that share a host by path therefore share the cookie's
  name too, and each would overwrite the other's session: give each a host of its own, or
  give the cookie a name without the prefix, as [below](#developing-without-https) but
  keeping `Secure`.
- **An application whose cookies a browser would refuse does not start.** A browser drops
  such a cookie and says nothing, so nobody could log in and nothing would show why. When the
  application begins to serve, asfquart checks the settings it has ended up with, and raises
  a `RuntimeError` that names what is wrong:

  | The name begins with | Refused if |
  |---|---|
  | `__Host-` | `SESSION_COOKIE_SECURE` is off, or `SESSION_COOKIE_DOMAIN` is set, or the path (`SESSION_COOKIE_PATH`, or else `APPLICATION_ROOT`) is not `/` |
  | `__Secure-` | `SESSION_COOKIE_SECURE` is off |
  | anything else | never |

  The cookie for a login is checked in the same way, for `STATE_COOKIE_SECURE`, in an
  application that has the OAuth endpoint.
- **Upgrading from 0.1.12 logs everybody out once.** A session cookie under the old name,
  `session`, is no longer read.

### Developing without HTTPS

A browser only keeps these cookies over HTTPS, as it only keeps any `Secure` cookie, and
asfquart's session cookie has always been `Secure`. Chrome and Firefox make an exception
for an address on the machine itself, such as `http://127.0.0.1:8000`: they keep `Secure`
cookies there, `__Host-` ones included, so an application run with `app.runx(port=8000)`
works in them without a certificate. Safari makes no such exception, and drops the session
cookie over plain HTTP whatever it is called. (Tried with Chrome 158, Firefox 152 and
Safari 26.5.)

Where a browser will not keep the cookies, the better way is to develop over HTTPS, with a
certificate for the machine (`mkcert` makes one) passed to `runx()` as `certfile` and
`keyfile`. Logging in through the ASF OAuth provider needs HTTPS in any case, as the provider
only sends the browser back to an `https` address.

To go without the prefix all the same, on a development machine and never in production,
take it off both cookies, and the `Secure` attribute with it:

```python
import asfquart
import asfquart.generics

asfquart.generics.STATE_COOKIE_NAME = "asfquart-oauth-state"
asfquart.generics.STATE_COOKIE_SECURE = False
app = asfquart.construct("myapp")
app.config["SESSION_COOKIE_NAME"] = "session"
app.config["SESSION_COOKIE_SECURE"] = False
```

## HTTP Basic authentication

asfquart can accept an `Authorization: Basic` header with a user's ASF id and password, and
check them against LDAP. **This is off by default.** An application that needs it asks for
it when it is constructed, and has to be installed with the LDAP libraries
(`asfquart[aioldap]`):

```python
app = asfquart.construct("myapp", basic_auth=True)
```

`basic_auth=True` fails when the application is constructed, with a `RuntimeError`, if the
LDAP libraries are not installed: an application that has been told to accept passwords and
cannot check them should not start. What is checked is that the libraries are there. Whether
the LDAP server can be reached is not checked at startup, since it may be down for a while
without that being a reason for the application not to start; see
[External services](external-services.md#ldap) for what happens to a request then.

Without `basic_auth=True`, a request with an `Authorization: Basic` header that reaches
`asfquart.session.read()`, as every endpoint under `@asfquart.auth.require` does, is answered
with `401 Basic authentication is not enabled`.

Think before turning it on:

- **It is a password with no second factor.** A login through the OAuth provider is subject
  to multi-factor authentication. Basic authentication is not, so it is a way round it. A
  session made this way has `mfa` set to `False`, and does not meet
  `Requirements.mfa_protected`.
- **The application sees the password**, on every request.
- **Every request is checked against LDAP**, and so is every wrong guess. asfquart does not
  limit how often a client may try, so that has to be done in front of the application.
- **The session has less in it**: `uid`, `committees` and `projects`. `is_member`, `is_chair`
  and `is_root` are not looked up, so the requirements that read them are not met.

For a script or a service, a token is the better fit; see the next section. For how the
username and password are checked, and what happens when LDAP cannot be reached, see
[External services](external-services.md#ldap).

In asfquart 0.1.12 and earlier, Basic authentication was always on.

## Role account management via declared PAT handler
Role accounts (or regular users) can access asfquart apps by using a bearer token, so long as a personal app token (PAT) handler
is declared:

```python
async def token_handler(token):
    if token == "abcdefg":
        return {
            "uid": "roleaccountthing",
            "roleaccount": True,  # For role accounts, this MUST be set to True, to distinguish from normal user PATs
            "committees": ["httpd", "tomcat"],  # random restriction in this example
            "metadata": {  # the optional metadata dict can be used to manage/log whatever internal information you wish
                "scope": ["scopeA", "scopeB"],  # For instance, you can log which scopes this token can be used within
            },
        }


asfquart.APP.token_handler = token_handler
```

This would enable the role account to be granted a session through the bearer auth header:

```bash
curl -H "Authorization: bearer abcdefg" https://foo.apache.org/some-endpoint
```

## Using scopes for tokens
If the application makes use of scopes to limit what an access token can do, you can note these scopes inside the
`metadata` dictionary when constructing the session dict to return. The `metadata` dict can be used for whatever
information you wish to keep about a specific session, and is accessed through `session.metadata` when fetched via
the usual `session = await asfquart.session.read()` call. Thus, you can test your tokens at the endpoint:

```python
REQUIRED_SCOPE = "admin"  # some random scope required for this endpoint


@app.route("/foo")
@asfquart.auth.require  # Require a valid session, can be through a PAT
async def endpoint():
    # Get session
    session = await asfquart.session.read()
    # Ensure it has the right scope, or bail
    if REQUIRED_SCOPE not in session.metadata.get("scope", []):
        raise asfquart.auth.AuthenticationFailed("Your token does not have the required scope for this endpoint")
    # No bail? scope must be proper, do the things..
    do_scoped_stuff()
```
