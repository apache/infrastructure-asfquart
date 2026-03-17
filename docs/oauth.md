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

## Multi-instance limitation

OAuth state parameters are stored in a process-local dictionary in `src/asfquart/generics.py`:

```python
pending_states = {}  # keeps track of pending states and their expiry
```

In a multi-instance or load-balanced deployment, if the OAuth callback is routed to a different instance than the one that initiated the flow, the state lookup will fail because `pending_states` is not shared across processes.

See [ASVS report](https://github.com/apache/infrastructure-asfquart/issues/52)
