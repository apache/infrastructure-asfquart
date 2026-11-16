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
session = await asfquart.session.read(expiry_time=24*3600)  # Require a session that has been accessed in the past 24 hours.
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

## Role account management via declared PAT handler
Role accounts (or regular users) can access asfquart apps by using a bearer token, so long as a personal app token (PAT) handler
is declared:

```python
async def token_handler(token):
   if token == "abcdefg":
      return {
         "uid": "roleaccountthing",
         "roleaccount": True,  # For role accounts, this MUST be set to True, to distinguish from normal user PATs
         "committees": ["httpd", "tomcat",],  # random restriction in this example
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
