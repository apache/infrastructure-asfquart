# Limits

asfquart puts limits on how long things last, how large they may be, and how many of them
there may be. They are described where they belong, in the pages on OAuth, sessions and
forms. This page brings them together: each limit, its default, what happens when it is
reached, how to change it, and where it is in the source. It ends with the things that have
no limit, which an application or the proxy in front of it may want to limit itself.

Each limit is counted in the process. An asfquart application runs as
[one process](one-process.md); with more than one, each would apply these limits on its own.

## Logging in

These are in `asfquart/generics.py`, and are explained in [Setting up OAuth](oauth.md).

| Limit | Default | When it is reached | To change it |
|---|---|---|---|
| Time to complete a login, from starting it to coming back from the OAuth provider | 900 seconds (15 minutes) | The callback is a `403`, and the user starts again | `workflow_timeout` argument of `setup_oauth()` |
| Logins that are started and not yet completed | 10,000 | The oldest is dropped to make room, and fails with a `403` if its user completes it. A warning is logged, at most once a minute | `max_pending_logins` argument of `setup_oauth()`, or `generics.DEFAULT_MAX_PENDING_LOGINS` |
| Uses of a `state` | One | A second callback with the same `state` is a `403` | Not adjustable |
| Length of a redirect target (`?login=`, `?logout=`) | 2,048 characters | `400` | `generics.MAX_REDIRECT_URI_LENGTH` |
| Exchange with the OAuth provider: connecting | 10 seconds | The login fails with a `403`, and the reason is logged | `generics.OAUTH_TIMEOUT` |
| Exchange with the OAuth provider: between reads | 15 seconds | The same | `generics.OAUTH_TIMEOUT` |
| Exchange with the OAuth provider: in all | 30 seconds | The same | `generics.OAUTH_TIMEOUT` |
| Attempts at the exchange | One: it is not tried again, and a redirect is not followed | The login fails with a `403` | Not adjustable |
| TLS version for the exchange | 1.2 or later | The login fails with a `403` | Not adjustable |

The cookie that ties a login to the browser that started it (`asfquart-oauth-state`) lasts as
long as the time to complete a login.

The OAuth provider has limits of its own, which asfquart does not set. For the ASF provider,
the `code` that it hands back is valid for 600 seconds and can be used once, according to
its maintainers. asfquart uses it at once, so the 900 seconds above is in practice the time
the user has to log in at the provider.

## Sessions

These are in `asfquart/session.py`, and are explained in [Session handling](sessions.md).
They apply to sessions kept in the cookie. With a [session store](session-stores.md) the
store applies its own limits, and these are not used.

| Limit | Default | When it is reached | To change it |
|---|---|---|---|
| Idle timeout: time since the session was last used | 7 days | The session ends; the user logs in again | `MAX_SESSION_IDLE` in `config.yaml`, in seconds; `0` for none. For one call, the `expiry_time` argument of `session.read()` |
| Maximum lifetime: time since the user logged in | 7 days | The same | `MAX_SESSION_AGE` in `config.yaml`, in seconds; `0` for none |
| How often the time of last use is saved to the cookie | Once in 60 seconds, or a tenth of the idle timeout if that is less | Not a limit that is reached: it is how exact the idle timeout is | `session.SESSION_REFRESH_INTERVAL` |
| Age of the cookie's signature | 31 days | The cookie is not accepted, and there is no session | quart's `PERMANENT_SESSION_LIFETIME` |
| Size of the session cookie | About 4 KB | Browsers do not store a larger cookie, so the session is lost. A Python `UserWarning` is given when one is sent | Keep less in the session, or use a session store |
| Life of the session cookie in the browser | Until the browser is closed | The cookie is gone, and the user logs in again | Not adjustable |

Two of these need explaining:

- **The age of the signature** is checked by quart, not by asfquart. The cookie is signed
  again whenever asfquart saves it, which is at least once a minute while the session is in
  use. So this is a second idle timeout, of 31 days, which applies even when
  `MAX_SESSION_IDLE` and `MAX_SESSION_AGE` are both `0`: "no limit" then means that a session
  in use never ends, and one left unused for 31 days does.
- **The size of the cookie** is a limit on what a session can hold. What the OAuth provider
  says about a user, the lists of projects and committees above all, has to fit. The session
  is compressed before it goes into the cookie, so the limit is on its compressed size, and
  text that repeats itself takes little room.

The session cookie is `Secure`, `HttpOnly` and `SameSite=Strict`. A session id, with a
session store, is 20 random bytes.

## Requests

These are in `asfquart/utils.py`, and are explained in
[Form data and its size limit](forms.md). The others are quart's.

| Limit | Default | When it is reached | To change it |
|---|---|---|---|
| Size of a form read by `formdata()` | 102,400 bytes (100 KB) | `413` | `MAX_FORM_CONTENT_LENGTH` in the app's config; `None` for none |
| Size of any request body (quart) | 16 MB | `413` | quart's `MAX_CONTENT_LENGTH` |
| Time for a request body to arrive (quart) | 60 seconds | `408` | quart's `BODY_TIMEOUT` |
| Time for a response to be sent (quart) | 60 seconds | quart gives up on sending it | quart's `RESPONSE_TIMEOUT` |
| Fields in a multipart form (quart) | 1,000 | `413` | quart's `MAX_FORM_PARTS` |
| Size of one field of a multipart form, other than a file (quart) | 500,000 bytes | `413` | quart's `MAX_FORM_MEMORY_SIZE` |

The lower of the first two is the limit for a form. A JSON body is limited by the second
alone. The last two are for `multipart/form-data` only, and the last is reached only by an
application that has raised the limit for forms above it.

## LDAP

These are in `asfquart/ldap.py`. They matter only to an application that accepts HTTP Basic
authentication; see [External services](external-services.md#ldap).

| Limit | Default | When it is reached | To change it |
|---|---|---|---|
| Time a user's project memberships are kept | 3,600 seconds (an hour) | They are looked up again at the user's next request | `ldap.DEFAULT_LDAP_CACHE_TTL` |
| Users whose memberships are kept | 1,000 | The one used longest ago is dropped, and looked up again when next needed | `ldap.DEFAULT_LDAP_CACHE_MAX_ENTRIES` |
| Time a request waits for LDAP to check a password and look up the memberships | 30 seconds | `500`, and the reason is logged. The work in LDAP is not stopped, and a connection that LDAP leaves unanswered is not covered; see below | `ldap.LDAP_TIMEOUT` |
| Time the LDAP library waits for a server that does not answer the connection. The whole application is stopped for that time; see below | 5 seconds, for each LDAP check | `500`, and the reason is logged | `LDAPNETWORK_TIMEOUT` in the environment that the application is started in; `ldap.LDAP_NETWORK_TIMEOUT` before the first LDAP check |
| Connections to LDAP being made at one time. The lookup of the memberships that follows is not counted | 1 | The others wait for their turn, within their 30 seconds | Not adjustable |
| LDAP checks going on at one time, counting those that a request has stopped waiting for | 10 | The request waits for one of them to end, in the order of arrival and within its 30 seconds. If none does: `500`, without asking LDAP, and the reason is logged at most once a minute | `ldap.MAX_LDAP_OPERATIONS` |
| Requests waiting for one of those checks to end | 100 | `500` at once, without asking LDAP, and the reason is logged at most once a minute | `ldap.MAX_LDAP_WAITING` |
| Attempts at an LDAP check | One: it is not tried again | `500` | Not adjustable |
| How often a wrong password is logged for one user | Once in 60 seconds, with a count of the failures in between | Not a limit on logging in: it keeps a flood of guesses from flooding the log | `ldap.FAILED_LOGIN_LOG_INTERVAL` |
| Users whose wrong passwords are being counted | 1,000 | The one that failed longest ago is dropped. The failures that were counted are logged first, and the user is logged again at their next failure | `ldap.MAX_FAILED_LOGIN_USERS` |
| Lines about wrong passwords, for all users together | 60 in 60 seconds | The failures past that are counted, and one line gives the count when the next 60 seconds begin. Not a limit on logging in | `ldap.FAILED_LOGIN_LOG_LIMIT` |

A change to a user's memberships in LDAP can therefore take up to an hour to be seen. The
password is not cached: it is checked against LDAP on every request.

The limits on waiting for LDAP and on LDAP checks work together. When LDAP has connected
and then does not answer, a request stops waiting after 30 seconds, but asfquart cannot stop
the work that it was waiting for: that goes on, in a thread, until LDAP answers, the
connection fails, or asfpy gives up. The limit on checks counts those as well, so that such
a server holds at most ten threads and connections, however many requests arrive. A request
that finds all ten taken waits for one, and that wait is part of its 30 seconds, so more
than ten requests at one time are served when LDAP answers. While all ten stay held, HTTP
Basic authentication fails for everybody, for each request after its 30 seconds, and at once
when a hundred are waiting; nothing else in the application is affected.

**Neither of those covers an LDAP server that does not answer the connection itself.** While
a connection to such a server is being attempted, the whole application is stopped: no
request is answered, of any kind, and the 30 seconds are not counted. The network timeout is
for that: it ends the stop after 5 seconds. asfquart makes one connection to LDAP at a time,
so the stops come one after another, with the application running in between, and a request
whose 30 seconds run out while it waits for its turn causes none. See
[When LDAP does not answer the connection](external-services.md#when-ldap-does-not-answer-the-connection).

## The application

| Limit | Default | When it is reached | To change it |
|---|---|---|---|
| Processes | One | See [One process](one-process.md) | Not adjustable |
| Time for a background task to finish when the application stops (quart) | 5 seconds | The task is cancelled | quart's `BACKGROUND_TASK_SHUTDOWN_TIMEOUT` |
| Permissions of the token file | `0600`: its owner only | A warning is printed when the application starts | Not adjustable |

The application secret that is generated for the token file is 32 random bytes. See
[The application secret](app-secret.md).

## The values

The limits above that are values in the code, with those values. `tests/limits.py` compares
this table with the code.

| Name | Value |
|---|---|
| `asfquart.generics.DEFAULT_MAX_PENDING_LOGINS` | `10000` |
| `asfquart.generics.MAX_REDIRECT_URI_LENGTH` | `2048` |
| `asfquart.generics.OAUTH_TIMEOUT.connect` | `10` |
| `asfquart.generics.OAUTH_TIMEOUT.sock_connect` | `10` |
| `asfquart.generics.OAUTH_TIMEOUT.sock_read` | `15` |
| `asfquart.generics.OAUTH_TIMEOUT.total` | `30` |
| `asfquart.session.DEFAULT_MAX_SESSION_IDLE` | `604800` |
| `asfquart.session.DEFAULT_MAX_SESSION_AGE` | `604800` |
| `asfquart.session.SESSION_REFRESH_INTERVAL` | `60` |
| `asfquart.utils.DEFAULT_MAX_FORM_CONTENT_LENGTH` | `102400` |
| `asfquart.ldap.DEFAULT_LDAP_CACHE_TTL` | `3600` |
| `asfquart.ldap.DEFAULT_LDAP_CACHE_MAX_ENTRIES` | `1000` |
| `asfquart.ldap.LDAP_TIMEOUT` | `30` |
| `asfquart.ldap.LDAP_NETWORK_TIMEOUT` | `5` |
| `asfquart.ldap.MAX_LDAP_OPERATIONS` | `10` |
| `asfquart.ldap.MAX_LDAP_WAITING` | `100` |
| `asfquart.ldap.FAILED_LOGIN_LOG_INTERVAL` | `60` |
| `asfquart.ldap.MAX_FAILED_LOGIN_USERS` | `1000` |
| `asfquart.ldap.FAILED_LOGIN_LOG_LIMIT` | `60` |
| `asfquart.base.SECRETS_FILE_MODE` | `384` |

`384` is `0600` written in decimal. The default of `workflow_timeout`, 900, is an argument of
`setup_oauth()` and has no name of its own; the tests check it as well.

And those that are quart's settings, with the values an asfquart application has unless it
sets them:

| Setting | Value |
|---|---|
| `MAX_CONTENT_LENGTH` | `16777216` |
| `BODY_TIMEOUT` | `60` |
| `RESPONSE_TIMEOUT` | `60` |
| `MAX_FORM_PARTS` | `1000` |
| `MAX_FORM_MEMORY_SIZE` | `500000` |
| `MAX_COOKIE_SIZE` | `4093` |
| `PERMANENT_SESSION_LIFETIME` | `31 days, 0:00:00` |
| `BACKGROUND_TASK_SHUTDOWN_TIMEOUT` | `5` |

## What has no limit

asfquart does not limit these. Where one is wanted, it has to come from the application, or
from the proxy in front of it, which is the only place that can tell one client from
another.

- **How often a client may make requests.** There is no rate limit of any kind: not on
  starting logins, not on failed logins, not on wrong passwords for HTTP Basic
  authentication, each of which is a connection to LDAP, and not on wrong bearer tokens.
- **How many sessions a user may have.** Logging in on another browser does not end the
  session on the first. With sessions kept in the cookie, asfquart has no record of the
  sessions that exist; a session store can count them and end them.
- **How long the application's `token_handler` may take**, or a session store's methods.
  They are called on the request, and the request waits.
- **How long an endpoint may take to answer**, other than quart's time for the response.
- **The size of a JSON body or an upload**, other than quart's limit on every request body.
- **What a session may hold**, other than what fits in the cookie. With a session store
  there is no limit but the store's own.
