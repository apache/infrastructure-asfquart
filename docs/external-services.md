# External services

asfquart depends on two services run by ASF Infrastructure: the OAuth provider, for logging
users in, and LDAP, for requests that authenticate with a username and password. This page
lists the endpoints, what each is used for, and what an application and its users see when
one of them cannot be reached.

| Endpoint | Constant | Used for | Contacted by |
|---|---|---|---|
| `https://oauth.apache.org/auth-oidc` | `asfquart.generics.OAUTH_URL_INIT` | Sending the user to log in | The user's browser |
| `https://oauth.apache.org/token-oidc` | `asfquart.generics.OAUTH_URL_CALLBACK` | Exchanging the code from the callback for the user's details | asfquart, once per login |
| `ldaps://ldap-eu.apache.org:636` | `asfquart.ldap.DEFAULT_LDAP_URI` | Checking a password and looking up project memberships | asfquart, on every request with an `Authorization: Basic` header |

Nothing else is contacted. Sessions are kept by the application (in a cookie, or in the store
set as `app.sessions`), and are not checked against either service once they exist.

## OAuth provider

A login is a round trip through the OAuth provider; see [OAuth workflows](oauth.md) for the
steps.

### Authorization endpoint (`OAUTH_URL_INIT`)

asfquart redirects the browser here when a login starts. asfquart makes no connection to
this endpoint itself, so it cannot tell whether it is available.

If it cannot be reached:

- The user sees an error from their browser, or from the provider, in place of the login
  page. They are not returned to the application.
- No session is created. The login that was started is abandoned, and expires after the
  workflow timeout (15 minutes by default).
- Users who are already logged in are not affected.

### Token endpoint (`OAUTH_URL_CALLBACK`)

When the browser returns from the provider, asfquart makes one `GET` request to this endpoint
to exchange the `code` for the user's details. The request is time limited: 10 seconds to
connect, 15 seconds between reads, and 30 seconds in total. It is not retried.

| What happens | Response to the user |
|---|---|
| The endpoint cannot be reached, or does not answer in time | `403 OAuth authentication failed.` |
| The endpoint answers with a status other than `200` | `403 OAuth authentication failed.` |
| The answer is not a JSON object with a valid `uid` | `403 OAuth authentication failed.` |

In each of these cases:

- No session is created, and the user is not logged in.
- The `state` of that login has been used up, so the user has to start a new login; reloading
  the page does not retry the exchange.
- When the endpoint could not be reached or did not answer in time, a warning is logged
  (`OAuth code exchange failed`), with the kind of error and without the `code`.
- Users who are already logged in are not affected.

So while the OAuth provider is down, nobody can log in, and everybody who is logged in can
carry on until their session expires.

## LDAP

LDAP is used only for requests that carry an `Authorization: Basic` header, and only when:

- the app was constructed with `basic_auth=True` (the default), and
- the `aioldap` extra is installed (`asfquart[aioldap]`).

Without the extra, such a request is treated as having no session. With `basic_auth=False`
it is answered with `401 Basic authentication is not enabled`. In neither case is LDAP
contacted.

For each such request asfquart connects to LDAP as the user, which checks the password, and
looks up the projects that the user is a member or owner of. The lookup is cached in memory
for an hour per user. The password is checked on every request, cached or not, so the cache
saves the lookup but not the connection.

| What happens | Response to the user |
|---|---|
| LDAP refuses the username and password | `403 Invalid credentials provided` |
| LDAP cannot be reached, fails, or returns nothing | `500 Could not perform LDAP authorization check, please try again later.` |

When LDAP cannot be reached:

- Every request that uses `Authorization: Basic` fails with the `500` above, including
  those of users whose memberships are cached.
- The error is printed to standard output (`Base exception during LDAP lookup`).
- asfquart sets no timeout of its own on the connection, and does not retry. There is one
  server, and no fallback.
- OAuth logins, sessions, and bearer tokens are not affected: they do not use LDAP.

## Using other endpoints

The endpoints are module-level constants, and are read when they are used. An application can
point asfquart at other servers, a test OAuth provider for instance, by assigning to them
before the first request:

```python
import asfquart
import asfquart.generics

asfquart.generics.OAUTH_URL_INIT = "https://oauth.example.org/auth?state=%s&redirect_uri=%s"
asfquart.generics.OAUTH_URL_CALLBACK = "https://oauth.example.org/token?code=%s"

app = asfquart.construct("myapp")
```

`OAUTH_URL_INIT` takes the state and the callback URL, and `OAUTH_URL_CALLBACK` takes the
code, each as a `%s`.
