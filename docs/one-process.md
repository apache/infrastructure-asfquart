# One process

An asfquart application runs as **one process**: one instance of the application, served by
one worker. That is the only arrangement that asfquart supports today.

This page says which parts of asfquart assume a single process, what goes wrong with more
than one, and what would have to change before an application could be run as several
processes, or on several servers behind a load balancer. It describes; it does not decide.
Whether asfquart should support more than one process is the question in
[issue 160](https://github.com/apache/infrastructure-asfquart/issues/160).

## What this rules out

- More than one worker: `hypercorn --workers 2 myapp:app`, or any server that forks.
- More than one instance of the same application behind a load balancer or a round-robin
  proxy, on one host or on several.
- Two copies running side by side during a deployment, both receiving requests, where one is
  started before the other is stopped.

Running `app.runx()`, or `hypercorn myapp:app` with its default of one worker, is one
process. So is a single instance behind a reverse proxy such as httpd.

Several *different* applications on one host are not affected. Each has its own name, its own
directory and its own session cookie, and none of them shares anything with the others.

## What assumes one process

| Part | Where it is kept | With two processes |
|---|---|---|
| Logins in progress | Memory of the process | A login that starts in one and returns to the other fails |
| The application secret | A file, created at startup | The two can start with different secrets, and refuse each other's sessions |
| Background tasks | Run inside the process | Every task runs once in each process |
| Restart and reload | The process restarts itself | Each process restarts on its own; nothing coordinates them |
| The LDAP cache | Memory of the process | Works, but each process does its own lookups |
| Limits | Counted in the process | Each limit applies to each process separately |

Sessions themselves are not in this table. They are covered below, under "What already
works".

### Logins in progress

When a login starts, asfquart records its `state` in a dictionary in the memory of the
process (`pending_states`, in `generics.py`), and sends the browser to the OAuth provider.
When the browser comes back, asfquart looks the `state` up in that dictionary. See
[OAuth workflows](oauth.md).

With two processes, the request that starts the login and the callback that completes it can
reach different ones. The second has no record of the `state`, and answers `403 Invalid or
expired OAuth state provided`. With two processes sharing requests evenly, about half of all
logins fail.

This is the part that fails most visibly, and the first that would have to change.

### The application secret

At startup asfquart reads the secret from the token file, and creates the file if it is not
there. See [The application secret](app-secret.md). Two processes that start at the same
moment, in a directory that has no token file yet or has an empty one, can each generate a
secret:

- One creates the file. The other finds that the file has just appeared, cannot create it,
  logs `Session permanence cannot be guaranteed!`, and carries on with a secret of its own
  that is only in its memory.
- Or the second finds the file created but not yet written, takes it for an empty file, and
  writes a new secret into it, while the first keeps the one it generated.

Either way the two processes hold different secrets until both are restarted. Each refuses
the session cookies that the other signed, so a user is logged in to one process and not to
the other, from one request to the next.

Once the file exists and has a secret in it, any number of processes read the same secret
from it, and this does not arise. It is a problem of the first start only.

### Background tasks

`app.add_runner()` starts a long-running task when the application starts, and cancels it
when it stops. asfquart uses this for its template watcher, and applications use it for jobs
of their own: polling something, sending queued mail, expiring old records.

Each process runs every runner. For the template watcher that is harmless. For a job that
must happen once, such as sending a message, it means that the job happens once per process.

### Restart and reload

`app.runx()` runs the application in the process that calls it. It watches the source and
configuration files and restarts the process when one changes, restarts it on `SIGUSR2`, and
shuts it down on `SIGINT` or `SIGTERM`. There is no parent process and there are no workers:
"restart" means that the process replaces itself.

With several processes, each one watches the files and restarts on its own, at whatever
moment it notices the change. Nothing starts them, stops them, or makes sure that one is
serving while another restarts.

### The LDAP cache

Project memberships that are looked up in LDAP, for HTTP Basic authentication, are cached for
an hour in the memory of the process (`LDAP_CACHE`, in `ldap.py`). With several processes
each has its own cache, so the same user is looked up once per process, and a change in LDAP
reaches the processes at different times, up to an hour apart. Nothing fails.

### Limits

Where asfquart puts a limit on what it keeps in memory, the limit is counted in the process.
With several processes the total is that many times the limit, and anything that is counted
or limited per user or per client is counted by each process separately.

## What already works

Not everything would need to change.

- **Sessions kept in the cookie.** The whole session travels with each request, and any
  process that has the same secret can read it. Nothing is kept on the server.
- **Sessions kept in a store** (`app.sessions`), if the store keeps them somewhere that all
  the processes share, such as a database. A store that keeps them in memory is per process.
- **Handling a request.** Apart from the parts above, a request does not depend on anything
  that an earlier request left in the process.
- **Bearer tokens** (`app.token_handler`): each request carries its token, and the handler
  is the application's own.
- **Templates and configuration**, which every process reads from the same files.

## What would have to change

In the order in which they would bite.

### 1. Logins in progress need a home outside the process

There are three ways to do it, and they are not equally good.

- **A shared store.** Keep the pending logins where every process can reach them, with an
  expiry: a database table or a cache server. The natural shape is a small interface that the
  application supplies, as it supplies `app.sessions`, with asfquart's dictionary as the
  default for a single process. Taking a login out of the store when its callback arrives has
  to be atomic, so that a `state` cannot be used twice by two processes at once.
- **No store at all.** Put what asfquart needs to know about the login (when it started,
  where to go afterwards, which browser started it) into a value that is signed with the
  application secret, and carry it in the `state` or in a short-lived cookie. Any process can
  then check a callback. What is lost is single use: nothing records that a `state` has been
  used, so the same callback could be replayed until it expires, unless a shared record of
  used states is kept after all.
- **Sticky routing.** Have the load balancer send each browser to the same process every
  time. This needs no change to asfquart, but it is a property of the deployment and not of
  the application, it fails whenever the routing changes, and it does nothing for a restart.

### 2. The secret has to be the same everywhere, from the first start

- **Today, without changing asfquart:** give every process the same secret from outside.
  Either put the token file in place before any of them starts, or construct the application
  with `token_file=None` and set `app.secret_key` from wherever the deployment keeps its
  secrets. Both are described in [The application secret](app-secret.md). On several servers
  this is the only way, since they do not share a file.
- **To make the token file safe on one host:** create it atomically. Write the secret to a
  temporary file in the same directory, and link or rename it into place without replacing a
  file that is already there. A process that loses that race reads the winner's file, instead
  of keeping a secret of its own. The empty-file case needs the same care.

### 3. Background tasks need to say where they run

A runner would have to declare whether it runs in every process or in one. Running in one
needs either a lock that the processes contend for, such as a file lock on one host or a row
in a database across several, or a separate process that runs the once-only jobs and serves
no requests. The second is simpler and is what most deployments do.

### 4. Something has to manage the processes

`runx()` would stay as it is, for development and for single-process use. Several processes
need a manager outside the application: Hypercorn's own workers, or one service unit per
instance. Reload on file change belongs to development and would be off in that arrangement.
A deployment would restart the processes one at a time, which only works once parts 1 and 2
are done, because until then a restart loses logins in progress either way.

### 5. Caches and limits

The LDAP cache can stay per process. If the repeated lookups mattered it could move to a
shared cache, but nothing is wrong without that. Each limit would have to be looked at in
turn: is it there to protect the memory of one process, in which case counting per process is
right, or to limit what one client may do, in which case it has to be counted in one place.

### 6. The application's own state

The same question applies to everything that an application keeps in memory between
requests: a module-level dictionary, a cache, a counter, a session store that keeps sessions
in memory. asfquart cannot see these. An application that is to run as several processes
has to go through its own code as this page goes through asfquart's.

## In short

| | Needed for more than one process |
|---|---|
| Logins in progress | A shared store, or signed state |
| The application secret | Supplied from outside, or a token file that is created atomically |
| Background tasks | A way to run a task in one process only |
| Process management | A manager outside the application; no self-restart |
| LDAP cache | Nothing |
| Limits | A review of each one |
| Cookie sessions | Nothing, given a shared secret |
| Session stores | A store that all the processes share |

The first two are what stand between asfquart and running as several processes at all. The
rest decide how well it would run.
