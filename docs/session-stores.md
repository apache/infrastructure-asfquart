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
  is `None` when the browser had no session. This is the better of the two to have, as the
  store can make the change in one step, and can carry the creation time over from the old
  session so that replacing a session does not extend its life.
- Otherwise asfquart calls `destroy(old_hsid)`, if there was a session, and then
  `register(new_hsid, session)`.
- A store with neither method cannot be used with `areplace()`. The other functions work
  without them.

## The session object

What `validate()` returns is handed to the application as the session. asfquart itself asks
two things of it:

- The `@asfquart.auth.require` decorator reads attributes from it: `isMember`, `isChair`,
  `isRoot`, `isRole`, `mfa` and `committees`, depending on the requirement. An application's
  own code will expect `uid` and the rest as well.
- The OAuth endpoint shows the session to a logged-in user who asks for it (`/auth`). For
  that the object must be a dictionary, or have a `model_dump()` method that returns one.

`asfquart.session.ClientSession` meets both, and is what a session is without a store:

```python
session = asfquart.session.ClientSession(session_data)
```

One thing to watch: build a `ClientSession` from the dictionary that `create()` was given,
and keep *that* dictionary in the store. A `ClientSession` does not turn back into the same
dictionary. The provider's `pmcs`, for instance, becomes `committees`, and making a second
`ClientSession` from the first would lose it.

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
  of the application. One that keeps them in memory, like the one below, serves one.

The application secret (the token file, `apptoken.txt`) is still needed with a store: the
cookie that carries the session id is signed with it. Changing the secret makes every session
id unusable, and the sessions that are left in the store can be removed.

## A store to read

This is a complete store that keeps its sessions in memory. It is here to show the interface
in one piece, and it is the store that asfquart's own tests use (`tests/session_store.py`
runs the code on this page). It is not for a deployed application: its sessions are lost when
the process stops, and are not shared between processes.

```python
import time

import asfquart.session


class MemoryStore:
    """Sessions kept in the memory of one process."""

    def __init__(self, max_idle=86400, max_age=7 * 86400):
        self.max_idle = max_idle  # seconds a session may go unused
        self.max_age = max_age    # seconds a session may last, used or not
        self._sessions = {}       # hsid -> [time created, time last used, session]

    def _ended(self, entry, now):
        created, last_used, _session = entry
        return last_used < now - self.max_idle or created < now - self.max_age

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
        self._sessions[hsid] = [now, now, asfquart.session.ClientSession(session_data)]

    async def validate(self, hsid):
        entry = self._sessions.get(hsid)
        if entry is None:
            return None
        now = time.time()
        if self._ended(entry, now):
            del self._sessions[hsid]
            return None
        entry[1] = now
        return entry[2]

    async def destroy(self, hsid):
        self._sessions.pop(hsid, None)

    async def replace(self, old_hsid, new_hsid, session):
        now = time.time()
        old = self._sessions.pop(old_hsid, None)
        created = old[0] if old is not None else now  # replacing a session does not extend its life
        self._sessions[new_hsid] = [created, now, session]

    def revoke(self, uid):
        """Ends every session of one user. Not part of the interface: the application calls it."""
        ended = [hsid for hsid, entry in self._sessions.items() if entry[2].uid == uid]
        for hsid in ended:
            del self._sessions[hsid]
        return len(ended)
```
