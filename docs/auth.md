# Authentication, Authorization, and Access

asfquart has built-in decorators for easily handling AAA (Authentication, Authorization, and Access)
for requests. These decorators have been built with the organizational structure of the ASF in mind,
and allow you to tailor access to each end-point to suit your specific requirements. These decorators will,
unless otherwise specified, automatically initiate an OAuth flow if unauthenticated access is attempted.

At present, asfquart features the following auth requirements:

- `asfquart.auth.Requirements.committer`: User must be logged in. Any session passes, which at
  the ASF means a committer; see [What `committer` means](#what-committer-means)
- `asfquart.auth.Requirements.member`: User must be a member of the Foundation to access
- `asfquart.auth.Requirements.pmc_member`: User must be a PMC member of any top-level project
- `asfquart.auth.Requirements.chair`: User must be a chair of one or more projects
- `asfquart.auth.Requirements.root`: User must be a member of infra-root
- `asfquart.auth.Requirements.mfa_protected`: User must have logged in with multi-factor authentication
  (previously `mfa_enabled`, which still works)
- `asfquart.auth.Requirements.roleacct`: User is a service account

These requirements can be passed to the `asfquart.auth.require` decorator to create a list of requirements
that must pass in order to make use of the endpoint.

By default, requirements are implicitly in the `all_of` category, meaning they are AND'ed together.
You can also OR requirements by using the `any_of` flag instead:

```python
@asfquart.auth.require   # Require a valid session of any kind (implicitly, committer)
async def func():
   pass

@asfquart.auth.require({req1, req2})  # Chain two requirements for this endpoint, implicitly AND
async def func():
  pass

@asfquart.auth.require(all_of={req1, req2})  # Same but with explicit AND
@asfquart.auth.require(any_of={req1, req2})  # Same but with explicit OR instead

# You can also use both, such as requiring (req1 AND req2) AND (either req3 OR req4)
@asfquart.auth.require(all_of={req1, req2}, any_of={req3,req4})

# Requirements given as the first argument are all_of requirements. They are added to any
# given with all_of: this requires req1 AND req2 AND (either req3 OR req4)
@asfquart.auth.require(req1, all_of=req2, any_of={req3, req4})
```

Requirements are checked when the endpoint is defined. Anything that is not a method of
`asfquart.auth.Requirements` (or of a subclass of it) raises a `TypeError`, as does using a
bare `@asfquart.auth.require` on a function that is not `async`.

### What a requirement reads from the session

Requirements don't check the session's class. Without a session store the session is an
`asfquart.session.ClientSession`, which has everything below. With a session store
(`app.sessions`) it's whatever the store returns, so that object needs the attribute for each
requirement the application uses:

| Requirement | Reads |
|---|---|
| `committer` | Nothing - any session passes |
| `member` | `is_member` |
| `pmc_member` | `committees` |
| `chair` | `is_chair` |
| `root` | `is_root` |
| `mfa_protected` | `mfa` |
| `roleacct` | `is_role` |

These, plus `uid`, make up `asfquart.session.SessionProtocol`, which a type checker can check
a session class against. If a session is missing an attribute that a requirement reads,
`@asfquart.auth.require` raises a `TypeError` naming it and the endpoint isn't run.

Until 0.2.0, `is_member`, `is_chair`, `is_root` and `is_role` were `isMember`, `isChair`,
`isRoot` and `isRole`. The old names still work, with a `DeprecationWarning`, both on a
`ClientSession` and on a session store's own class. A `ClientSession` is also a dictionary, and
its keys keep the old names, so what `/auth` returns is unchanged.

## What `committer` means

`Requirements.committer` passes for any session, and reads nothing from it. It is the same
test as a bare `@asfquart.auth.require`, under a name that says who is expected.

The name is right for the ASF because of where sessions come from. The ASF OAuth provider,
and LDAP for HTTP Basic authentication, only know ASF accounts, and an ASF account belongs to
a committer. Being logged in and being a committer are then the same thing.

It is not a test of anything more than that:

- **It does not look at projects.** A committer who is in no project group passes: one whose
  projects have retired, say. To require membership of a project, test `projects` or
  `committees` in a requirement of your own.
- **A role account passes.** A session that the application's `token_handler` returns for a
  service account is a session.
- **Any session that the application writes passes**, whatever is in it. An application that
  logs users in from somewhere other than the ASF OAuth provider cannot take `committer` to
  mean a committer.

Where one of these matters, add a requirement of your own. A requirement is a class method of
a subclass of `Requirements` that takes the session and returns whether it passes, with the
message for when it does not:

```python
import asfquart
import asfquart.auth


class MyRequirements(asfquart.auth.Requirements):
    E_NOT_A_PERSON = "This endpoint is not open to role accounts."
    E_NOT_IN_A_PROJECT = "This endpoint is only accessible to committers of a project."

    @classmethod
    def person(cls, client_session):
        """A user who logged in, and not a role account with a token"""
        return client_session.is_role is not True, cls.E_NOT_A_PERSON

    @classmethod
    def project_committer(cls, client_session):
        """A member of at least one project group"""
        return bool(client_session.projects), cls.E_NOT_IN_A_PROJECT


@asfquart.APP.route("/people-only")
@asfquart.auth.require(MyRequirements.person)
async def people_only():
    return "No role accounts here"


@asfquart.APP.route("/project-committers")
@asfquart.auth.require({MyRequirements.person, MyRequirements.project_committer})
async def project_committers():
    return "Committers of a project"
```

## Examples

The example below shows how to cordon off specific end-points to certain groups of users:

```python
import asfquart
from asfquart.auth import Requirements as R

APP = asfquart.APP


# URL that requires some sort of ASF auth (oauth, a token, or ldap if the app has basic_auth=True)
@APP.route("/foo")
@asfquart.auth.require  # Bare decorator means just require a valid session
async def view_that_requires_auth():
    pass


# URL that requires 2FA (implies oauth since ldap doesn't have 2fa)
@APP.route("/foo2fa")
@asfquart.auth.require({R.mfa_protected})
async def view_that_requires_2fa_auth():
    pass


# URL that requires a certain org role (2FA implied??)
@APP.route("/foorole")
@asfquart.auth.require({R.member})
async def view_that_requires_member_role():
    pass


# URL that needs at least one of multiple requirements, using the any_of directive
@APP.route("/multirole")
@asfquart.auth.require(any_of={R.member, R.chair})  # Either chair or member (or both) required
async def view_that_requires_some_role():
    pass
```
