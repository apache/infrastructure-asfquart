# External services

asfquart depends on two services run by ASF Infrastructure: the OAuth provider, for logging
users in, and LDAP, for requests that authenticate with a username and password. This page
lists the endpoints, what each is used for, and what an application and its users see when
one of them cannot be reached.

| Endpoint | Constant | Used for | Contacted by |
|---|---|---|---|
| `https://oauth.apache.org/auth-oidc` | `asfquart.generics.OAUTH_URL_INIT` | Sending the user to log in | The user's browser |
| `https://oauth.apache.org/token-oidc` | `asfquart.generics.OAUTH_URL_CALLBACK` | Exchanging the code from the callback for the user's details | asfquart, once per login |
| `ldaps://ldap-eu.apache.org:636` | `asfquart.ldap.DEFAULT_LDAP_URI` | Checking a password and looking up project memberships | asfquart, on every request that has an `Authorization: Basic` header and no session cookie |

asfquart itself contacts nothing else. By default sessions are kept in a cookie, and are not
checked against either service once they exist.

An application can add services of its own in two places, and their availability is then the
application's to document:

- `app.sessions`, a store for server-side sessions. It is called whenever the session is read
  for a request that has a session cookie, so a store that uses a database or another service
  is contacted that often.
- `app.token_handler`, which is called whenever the session is read for a request that has an
  `Authorization: Bearer` header and no session cookie, and may look the token up wherever
  it likes.

## OAuth provider

A login is a round trip through the OAuth provider; see [OAuth workflows](oauth.md) for the
steps.

### Authorization endpoint (`OAUTH_URL_INIT`)

asfquart redirects the browser here when a login starts. asfquart makes no connection to
this endpoint itself, so it cannot tell whether it is available.

If it cannot be reached:

- The user sees an error from their browser, or from the provider, in place of the login
  page. They are not returned to the application.
- No session is created. The login that was started is abandoned. Its `state` is no longer
  accepted after the workflow timeout (15 minutes by default), and the record of it is
  removed the next time a login starts or a callback arrives. However long the provider is
  down, no more than 10,000 such records are kept; see
  [Pending logins](oauth.md#pending-logins-and-restarting-the-application).
- Users who are already logged in are not affected.

### Token endpoint (`OAUTH_URL_CALLBACK`)

When the browser returns from the provider, asfquart makes one `POST` request to this endpoint
to exchange the `code` for the user's details, with the code in the form body rather than the
URL. Redirects aren't followed. The request is time limited: 10 seconds to
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
- A warning is logged (`OAuth code exchange failed: ...`) that tells the three rows above
  apart: the kind of error if the endpoint could not be reached, the status if it was not
  `200`, or which check the answer failed. It does not have the `code`, the `state`, or
  the answer itself.
- Users who are already logged in are not affected.

So while the OAuth provider is down, nobody can log in, and everybody who is logged in can
carry on until their session expires.

## LDAP

LDAP is used only for requests that carry an `Authorization: Basic` header, and only when:

- the request has no session cookie for the app. A session cookie is looked at first, and the
  `Authorization` header is then not read at all, even if the session in the cookie turns out
  to have expired;
- the app was constructed with `basic_auth=True` (it is off by default); and
- the `aioldap` extra is installed (`asfquart[aioldap]`).

Without `basic_auth=True` such a request is answered with `401 Basic authentication is not
enabled`, and LDAP is not contacted. With it, and without the extra, the app does not start:
`asfquart.construct()` raises a `RuntimeError`. See
[HTTP Basic authentication](sessions.md#http-basic-authentication).

For each such request asfquart connects to LDAP as the user, which checks the password, and
looks up the projects that the user is a member or owner of. The lookup is cached in memory
for an hour per user. The password is checked on every request, cached or not, so the cache
saves the lookup but not the connection.

The cache holds the lookups of at most 1,000 users (`asfquart.ldap.DEFAULT_LDAP_CACHE_MAX_ENTRIES`).
Lookups that are more than an hour old are removed whenever somebody authenticates, and when
the cache is full the lookup that has gone longest without being used makes way for the
newest, so a user who keeps coming back keeps their place. A user whose lookup is gone is
not refused: it is made again on their next request. Only a lookup that succeeded is cached,
so the cache does not grow with attempts to log in.

| What happens | Response to the user |
|---|---|
| LDAP refuses the username and password | `403 Invalid credentials provided` |
| LDAP cannot be reached, fails, or returns nothing | `500 Could not perform LDAP authorization check, please try again later.` |
| LDAP does not answer within 30 seconds | The same `500` |
| Ten LDAP checks are already going on | The request waits for one of them to end, within its 30 seconds. If none does, the same `500`, without asking LDAP |
| A hundred requests are already waiting for that | The same `500`, at once, without asking LDAP |

In every case the reason is in the application's log, and not in the response.
See [Failed logins](sessions.md#failed-logins) for what is logged.

When LDAP cannot be reached:

- Every request that authenticates with `Authorization: Basic` (and so has no session
  cookie) fails with the `500` above, including those of users whose memberships are cached.
- The error is logged on the `asfquart.ldap` logger.
- A request waits for LDAP for at most 30 seconds (`asfquart.ldap.LDAP_TIMEOUT`), which
  covers checking the password and looking up the memberships. It does not cover a
  connection that the server leaves unanswered: see
  [When LDAP does not answer the connection](#when-ldap-does-not-answer-the-connection).
- asfquart does not retry. A second attempt would be a second check of the password, against
  a server that is already in difficulty. There is one server, and no fallback.

What an LDAP server that has stopped answering does to the application depends on where it
stops. The two cases are very different.

### When LDAP does not answer the connection

This is a server that does not reply when the connection is opened, or that accepts it and
then says nothing while the encryption is set up. A host that is down behind a firewall
which drops packets looks like this, and so does a server that is overloaded or suspended.

- **The whole application stops, and not only the request that asked.** No other request is
  answered, with or without HTTP Basic authentication, and nothing is logged, until the
  attempt to connect ends. The connection is made by `asfpy.aioldap` in a thread of its own,
  but the LDAP library that it uses (bonsai) keeps hold of the Python interpreter while it
  connects, so no other thread runs, and the one that serves requests is among them.
- `LDAP_TIMEOUT` cannot end the wait, because it is counted by the part of the application
  that is stopped.
- What ends it is the network timeout of the LDAP library, which asfquart sets to 5 seconds
  (`asfquart.ldap.LDAP_NETWORK_TIMEOUT`). After that the request is the `500` above, and the
  application runs again. Without it there would be no end: in a test with asfpy 0.60, the
  application was still stopped when the test was ended after 45 seconds.
- asfquart sets it by putting `LDAPNETWORK_TIMEOUT=5` into the environment of the process.
  The LDAP library reads that once, at its first use, and there is no other way to set it
  that works for the connection. So it is done in `asfquart.construct(..., basic_auth=True)`,
  when the application starts and before its own code can have used the library. (An
  application that turns `app.basic_auth` on afterwards gets it at its first LDAP check, or
  can call `asfquart.ldap.set_network_timeout()` itself, as early as it can.) Three things
  follow:
  - To use another value, start the application with `LDAPNETWORK_TIMEOUT` set. A value that
    is already in the environment is left alone.
  - Assigning to `LDAP_NETWORK_TIMEOUT` works only before `construct()` is called.
  - Programs that the application starts afterwards inherit the variable, and those that use
    the same LDAP library (`ldapsearch`, for instance) get the same timeout.
- The 5 seconds are for each connection that is tried, and asfquart makes one connection at
  a time. Between two of them the application runs, and answers the requests that have
  collected. In a test, ten requests with HTTP Basic authentication that arrived together
  stopped the application six times for 5 seconds: six of them got the `500` one after
  another, and the other four when their 30 seconds were over, without a connection being
  tried for them. For as long as the server stays silent and such requests keep arriving,
  the application is stopped for most of the time.
- An application that does not accept HTTP Basic authentication (the default) never connects
  to LDAP, and none of this can happen to it.

### One connection at a time

asfquart connects to LDAP for one request at a time. The connection includes the check of
the password. The lookup of the memberships that follows is not held back, and those go on
side by side.

- With asfpy 0.60 and earlier this is needed for the network timeout to work at all. asfpy
  switches a setting of the LDAP library, for the whole process, around every connection.
  Connections that are made at the same time undo it for each other, and the timeout is
  then lost: in a test, the third of three requests that arrived together stopped the
  application, and it was still stopped when the test was ended.
- With a server that answers, it costs little: in a test, ten requests that arrived
  together were all answered in 0.2 seconds.
- A request that waits for its turn is waiting for LDAP, and its 30 seconds are counted. If
  they run out first, it gets the `500`, and no connection is made for it.

### When LDAP connects and then does not answer

This is a server that sets up the connection, and then does not reply to the password or
to the lookup of the memberships.

- Requests that do not use HTTP Basic authentication are not held up. This wait is in a
  thread of `asfpy.aioldap`, and the interpreter is free while it lasts.
- The request gives up after the 30 seconds, but the work it was waiting for cannot be
  stopped from asfquart. It goes on in its thread, holding its connection. With asfpy 0.60
  and earlier that is until LDAP answers or the connection fails. With the fix for
  [infrastructure-asfpy#72](https://github.com/apache/infrastructure-asfpy/issues/72),
  asfpy gives up after 30 seconds of its own, and the thread and the connection are
  released.
- If it is the password that gets no reply, that connection keeps its turn for as long, and
  the other requests with HTTP Basic authentication wait behind it and give up after their
  30 seconds.
- So that these do not pile up, at most 10 LDAP checks go on at one time
  (`asfquart.ldap.MAX_LDAP_OPERATIONS`). One that a request has given up on still counts
  until it really ends, and so does one that waits for its turn to connect.
- A request that arrives while there are 10 is not refused. It waits for one of them to end,
  behind the requests that came before it, and that wait is part of its 30 seconds. With a
  server that answers, more than 10 requests at one time are therefore all served, a little
  later. With a server that does not, each gets the `500` when its 30 seconds are over, and
  LDAP is not asked for it. The log says so, at most once a minute.
- At most 100 requests wait like that at one time (`asfquart.ldap.MAX_LDAP_WAITING`). They
  hold nothing in LDAP. A request past those is refused at once with the `500`.
- That is the most that such a server can hold: 10 threads and 10 connections, and 100
  requests that each wait up to 30 seconds. With asfpy 0.60 and earlier, if it never answers
  and the connections never fail, HTTP Basic authentication stays unavailable until the
  application is restarted.
- OAuth logins, sessions, and bearer tokens are not affected: they do not use LDAP.

## Using other endpoints

The endpoints are module-level constants, and are read when they are used. An application can
point asfquart at other servers, a test OAuth provider for instance, by assigning to them
before the first request:

```python
import asfquart
import asfquart.generics

asfquart.generics.OAUTH_URL_INIT = "https://oauth.example.org/auth?state=%s&redirect_uri=%s"
asfquart.generics.OAUTH_URL_CALLBACK = "https://oauth.example.org/token"

app = asfquart.construct("myapp")
```

`OAUTH_URL_INIT` takes the state and the callback URL, each as a `%s`. `OAUTH_URL_CALLBACK` is
just the endpoint - the code is POSTed to it as a form field named `code`.

Before 0.2.0 `OAUTH_URL_CALLBACK` took the code as a `%s`, and a lot of apps set it to the old
default, `"https://oauth.apache.org/token-oidc?code=%s"`. That exact value is treated as the new
default, so those apps get the `POST` and can drop the line. Any other value with a `%s` is
still sent as a `GET`, with a warning logged once - remove the query string to switch to
`POST`, if the endpoint accepts one.
