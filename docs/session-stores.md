# Session stores

By default asfquart keeps a user's session in the session cookie: everything that is known
about the user travels with each request. The cookie is signed, so nobody can alter it, but
it is not encrypted, and the application has no record of the sessions that exist. It cannot
list them, and it cannot end one except by waiting for it to expire.

An application that needs more than that can keep its sessions itself, in a *session store*.
The cookie then holds only a random session id, and the session is looked up in the store on
each request. Because the store is the application's own, it can:

- end a session at any time, for instance when an account is disabled,
- end every session of one user, or of all users,
- see who is logged in,
- keep more in a session than fits in a cookie, and keep it from the user's eyes.

## Using a store

A store is any object with the methods described below. Give it to the application after
constructing it, and before the first request:

```python
app = asfquart.construct("myapp")
app.sessions = MyStore()
```

**The store must be true when tested.** asfquart decides whether there is a store with
`if app.sessions:`, each time a session is read or changed, and not with a comparison to
`None`. An object is false if it has a `__len__()` that returns zero or a `__bool__()` that
returns `False`. A store written as a subclass of `dict`, or one that counts its sessions in
`__len__()`, is therefore false while it is empty, and it stays empty: asfquart takes it for
no store and keeps the whole session in the cookie, without any error. A class that defines
neither method is always true, as `MemoryStore` below is.

Reading a session is the same with a store as without one. `asfquart.session.read()`, the
`@asfquart.auth.require` decorator and the OAuth endpoint all use the store when there is one.

Changing a session is not the same. A store is asynchronous, so the functions to use are the
asynchronous ones:

| Without a store | With a store |
|---|---|
| `asfquart.session.write(data)` | `await asfquart.session.awrite(data)` |
| `asfquart.session.clear()` | `await asfquart.session.aclear()` |
| | `await asfquart.session.areplace(session)` |

`write()` and `clear()` raise a `RuntimeError` when the application has a store. `awrite()`
and `aclear()` also work without one, so code that has to run either way can use them
throughout.

## The session id

When a session is created, asfquart generates a random session id and puts it in the session
cookie. The store never sees that id. Each method is given its SHA3-256 hash instead, as a
string of 64 hexadecimal digits, called `hsid` below. The store uses the `hsid` as the key
under which it keeps the session.

The point of the hash is that what the store holds cannot be used to log in. Somebody who
reads the store's database learns the hashes, and cannot turn one back into the id that a
browser would have to present. For the same reason, treat an `hsid` as you would a password
hash, and keep it out of logs.

## The methods

A store has three methods, and may have two more. All of them are `async`.

| Method | Called when | Does |
|---|---|---|
| `create(hsid, session_data)` | A user has logged in, or the application called `awrite()` | Saves a new session |
| `validate(hsid)` | A session is read | Returns the session, or `None` if there is none or it has ended |
| `destroy(hsid)` | A user logs out, or a session is about to be replaced | Removes the session, if it is there |
| `replace(old_hsid, new_hsid, session)` (optional) | The application called `areplace()` | Puts `session` under the new id, in place of the old session |
| `register(new_hsid, session)` (optional) | The application called `areplace()`, and there is no `replace()` | Saves `session` under the new id |

### `create(hsid, session_data)`

`session_data` is a dictionary. After a login it is what the OAuth provider said about the
user, with `uid`, `fullname`, `email`, `pmcs`, `projects`, `isMember` and so on. From
`awrite()` it is whatever the application passed.

- Save it under `hsid`, with the time, so that `validate()` can tell how old the session is.
- Do not raise an error once the session has been saved. asfquart puts the session id in the
  cookie only after `create()` has returned, so an error at that point leaves a session in
  the store that no browser can reach.
- If the browser already had a session, asfquart calls `destroy()` for it first, and then
  `create()`. A user who logs in again therefore gets a new session id.

### `validate(hsid)`

This is called for every request that reads the session, so it should be quick.

- Return `None` for an `hsid` that is not in the store. asfquart then removes the session id
  from the cookie, and the request is treated as not logged in.
- **The store applies the time limits.** asfquart's `MAX_SESSION_AGE` setting and the
  `expiry_time` argument of `read()` are for sessions kept in the cookie, and are not used
  with a store. `validate()` should return `None`, and remove the session, when it has not
  been used for too long (an idle timeout) or was created too long ago (a maximum lifetime).
  An idle timeout only has an effect if it is the shorter of the two.
- Record that the session was used, if there is an idle timeout to keep.
- Whatever it returns is the session, as far as the application is concerned: it is what
  `asfquart.session.read()` returns. See "The session object" below for what it has to be.

### `destroy(hsid)`

Remove the session. It is not an error if there is none: the cookie may be older than the
store's record of it.

### `replace()` and `register()`

`asfquart.session.areplace(session)` gives the user a session that the application has
made itself, under a new session id. An application might do that to change what is in a
session, or to let an administrator act as another user. Unlike `awrite()` it passes a
finished session object, not a dictionary, and it does not call `create()`.

- If the store has `replace(old_hsid, new_hsid, session)`, that is the only call. `old_hsid`
  is `None` when the browser had no session. This is the better of the two to have, for the
  three reasons that follow.
  - The store can make the change in one step.
  - It can carry the creation time over from the old session, so that replacing a session
    does not extend its life.
  - It can see whether the old session is still there. `old_hsid` comes from the browser's
    cookie, and the session it names may have ended or been revoked, even since the
    application read it earlier in the same request. A session that has ended should not come
    back under a new id, so `replace()` should save nothing in that case. asfquart still puts
    the new id in the cookie, the next `validate()` returns `None` for it, and the user is
    logged out, which is what ending the session was meant to do.
- Otherwise asfquart calls `destroy(old_hsid)`, if there was a session, and then
  `register(new_hsid, session)`. `register()` is not told about the old session, so it cannot
  keep its creation time or tell that it had ended.
- A store with neither method **must not** be used with `areplace()`. asfquart finds that
  `register()` is missing only after it has called `destroy()`. The call fails with an
  `AttributeError`, and by then the user's session has been removed: the request is a `500`
  and the user is logged out. The other functions work without the two methods.

`areplace()` refuses a session object with no `uid` attribute, such as a plain dictionary,
with a `TypeError`, and leaves the user's session as it was. So a store can rely on
`session.uid` for any session passed to `replace()` or `register()`.

## The session object

What `validate()` returns is handed to the application as the session. asfquart itself asks
two things of it:

- It needs a `uid`, and the attribute for each `@asfquart.auth.require` requirement the
  application uses - see [what a requirement reads](auth.md#what-a-requirement-reads-from-the-session).
  `asfquart.session.SessionProtocol` is the full list.
- The OAuth endpoint shows the session to a logged-in user who asks for it (`/auth`). For
  that the object must be a dictionary, or have a `model_dump()` method that returns one.

`asfquart.session.ClientSession` meets both, and is what a session is without a store:

```python
session = asfquart.session.ClientSession(session_data)
```

One thing to watch: build a `ClientSession` from the dictionary that `create()` was given,
and keep *that* dictionary in the store. A `ClientSession` does not turn back into the same
dictionary. The provider's `pmcs`, for instance, becomes `committees`, and making a second
`ClientSession` from the first would lose it. The store below keeps the dictionary, and
makes a new `ClientSession` from a copy of it each time the session is read. A request that
changes its session object therefore does not change what is in the store, as it would not
with a store that keeps its sessions in a database.

## What a store has to look after itself

asfquart calls the store, and otherwise leaves the sessions to it.

- **Time limits**, as described under `validate()`.
- **Sessions that are never asked for again.** A user who closes the browser does not log
  out. Remove sessions that have passed their limits from time to time, or they stay for
  ever.
- **Ending sessions early.** asfquart has no call for this, because it is the store's own
  business: add whatever methods the application needs, such as one that removes every
  session of a user. A removed session stops working at the user's next request.
- **Errors.** An exception raised by the store is not caught by asfquart. The request fails
  with a `500`. If the store's database is unavailable, nobody can use their session, so the
  store is one more service that the application depends on.
- **Several processes.** A store that keeps its sessions in a database serves every process
  of the application. One that keeps them in memory, like the one below, serves one. See
  [One process](one-process.md).

The [application secret](app-secret.md) (the token file, `apptoken.txt`) is still needed with
a store: the cookie that carries the session id is signed with it. Changing the secret makes
every session id unusable, and the sessions that are left in the store can be removed.

## A store to read

This is a complete store that keeps its sessions in memory. It is here to show the interface
in one piece, and it is the store that asfquart's own tests use (`tests/session_store.py`
runs the code on this page). It is not for a deployed application: its sessions are lost when
the process stops, and are not shared between processes.

```python
import copy
import time

import asfquart.session


class MemoryStore:
    """Sessions kept in the memory of one process."""

    def __init__(self, max_idle=86400, max_age=7 * 86400):
        self.max_idle = max_idle  # seconds a session may go unused
        self.max_age = max_age    # seconds a session may last, used or not
        # hsid -> [time created, time last used, data, session]. A session made by create()
        # has its data, and one made by replace() has the session object it was given.
        self._sessions = {}

    def _ended(self, entry, now):
        created, last_used, _data, _session = entry
        return last_used < now - self.max_idle or created < now - self.max_age

    @staticmethod
    def _uid(entry):
        """Whose session this is"""
        _created, _last_used, data, session = entry
        return data.get("uid") if session is None else session.uid

    def purge(self):
        """Removes the sessions that have ended. Returns how many there were."""
        now = time.time()
        ended = [hsid for hsid, entry in self._sessions.items() if self._ended(entry, now)]
        for hsid in ended:
            del self._sessions[hsid]
        return len(ended)

    async def create(self, hsid, session_data):
        self.purge()
        now = time.time()
        self._sessions[hsid] = [now, now, copy.deepcopy(session_data), None]  # the data, as given

    async def validate(self, hsid):
        entry = self._sessions.get(hsid)
        if entry is None:
            return None
        now = time.time()
        if self._ended(entry, now):
            del self._sessions[hsid]
            return None
        entry[1] = now
        _created, _last_used, data, session = entry
        if session is not None:
            return session
        # A copy, so that a request which changes its session does not change the store's
        return asfquart.session.ClientSession(copy.deepcopy(data))

    async def destroy(self, hsid):
        self._sessions.pop(hsid, None)

    async def replace(self, old_hsid, new_hsid, session):
        now = time.time()
        created = now
        if old_hsid is not None:
            old = self._sessions.pop(old_hsid, None)
            if old is None or self._ended(old, now):
                return  # the session to replace has ended or was revoked: it does not come back
            created = old[0]  # replacing a session does not extend its life
        self._sessions[new_hsid] = [created, now, None, session]

    def revoke(self, uid):
        """Ends every session of one user. Not part of the interface: the application calls it."""
        ended = [hsid for hsid, entry in self._sessions.items() if self._uid(entry) == uid]
        for hsid in ended:
            del self._sessions[hsid]
        return len(ended)
```
