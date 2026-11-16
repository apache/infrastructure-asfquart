# The application secret

Every asfquart application has a secret, a random string that only the application knows.
It is used to sign the session cookie, so that a session cannot be read or made up by anyone
else. asfquart creates the secret, keeps it in a file, and reads it back when the application
starts. Most applications never have to think about it.

It is available as `app.secret_key` once the application has been constructed.

## Where it is kept

By default the secret is in `apptoken.txt`, in the application's directory (the `app_dir`
argument of `asfquart.construct()`, or the directory the application was started in).

- If the file is there when the application starts, the secret is read from it.
- If it is not, a new secret is generated (`secrets.token_hex()`, 256 random bits) and written
  to the file. The file is created with mode `0600`, so that only the user the application
  runs as can read it.
- If the file is there but empty, or has only whitespace in it, it is treated as missing: a
  new secret is generated and written to it, and a warning is logged. The file's mode is set
  to `0600` before the secret goes in. (A file can be left empty if the application is
  stopped just as it creates it.)
- If the file cannot be written, for want of permission or because the file system is
  read-only or full, the application still starts, with a secret that it only holds in
  memory, and logs `Session permanence cannot be guaranteed!`. See "Without a token
  file" below for what that means.
- If the file has any other mode than `0600`, a warning is written to standard error, and the
  file is used all the same. Fix the mode: anybody who can read the file can forge a session.

The `token_file` argument puts the file somewhere else. A relative path is taken from the
application's directory, and an absolute path is used as it is:

```python
app = asfquart.construct("myapp", token_file="secrets/apptoken.txt")
```

The file's content is used exactly as it is, including a newline at the end if there is one.
Leave the file as asfquart wrote it. If you must copy a secret from one host to another, copy
the file, and do not paste its content into an editor.

Keep the file out of version control and out of backups that are less well protected than
the application itself.

## Restarting

With a token file, restarting the application changes nothing: the same secret is read back,
and the cookies that users already have are still accepted.

An asfquart application runs as one process: one instance, with one worker. Sharing a token
file does not make it safe to run several. Logins in progress are kept in the memory of the
process that started them (see [Multi-instance limitation](oauth.md#multi-instance-limitation)),
and the token file is not created or replaced in a way that is safe for two processes that
start at the same moment: each can end up with a secret of its own, and refuse the other's
session cookies. See [issue 160](https://github.com/apache/infrastructure-asfquart/issues/160).

## Without a token file

`token_file=None` tells asfquart not to keep the secret in a file:

```python
app = asfquart.construct("myapp", token_file=None)
```

A new secret is then generated every time the application starts. Every session cookie from
before a restart is refused, and everybody has to log in again. That suits tests, and
applications that supply the secret themselves, as described below. It does not suit an
application that should keep its users logged in across a restart.

## Changing the secret

To replace the secret:

1. Stop the application.
2. Remove the token file.
3. Start the application. It generates a new secret and writes a new file.

Every session cookie that was signed with the old secret is refused from then on, and users
log in again. Nothing else is lost. An application with a session store (`app.sessions`)
still has its stored sessions, but no browser holds a cookie that leads to them any more, so
they are of no use and can be cleared out.

Replace the secret at once if it may have been disclosed, for instance if the token file was
readable by others or has ended up in a repository or a backup. Whether to replace it on a
schedule as well is for the application's own policy to say.

## Supplying the secret yourself

An application can keep the secret somewhere of its own, a secrets manager for instance, or
alongside other data that has to be reset together with the sessions. Construct the
application without a token file, and set `app.secret_key` before the first request:

```python
app = asfquart.construct("myapp", token_file=None)
app.secret_key = load_my_secret()    # the same value every time, from wherever it is kept
```

The secret is then the application's to look after:

- Use a long random value, such as `secrets.token_hex()` gives, and never a word or a phrase.
- Supply the same value at every start, or sessions will not outlast a restart.
- To log everybody out, supply a new value.

The other way round also works: let asfquart generate the secret, and read `app.secret_key`
after `asfquart.construct()` to store a copy of it.

## Loading configuration into the app

`app.secret_key` is the same thing as the `SECRET_KEY` entry of `app.config`. Anything that
loads a whole configuration into `app.config` can therefore replace the secret, and
`app.config.from_object()` does so even when the object's `SECRET_KEY` is `None`. The
application is then left with no secret, and fails with `The session is unavailable because no
secret key was set` as soon as a session is written.

Keep the secret across such a call:

```python
app = asfquart.construct("myapp")
secret_key = app.secret_key
app.config.from_object(MySettings)
app.secret_key = secret_key
```

asfquart's own settings, in `config.yaml`, are kept in `app.cfg` and do not touch the secret.
