# Authentication, Authorization, and Access

asfquart has built-in decorators for easily handling AAA (Authentication, Authorization, and Access) 
for requests. These decorators have been built with the organizational structure of the ASF in mind, 
and allows you to tailor access to each end-point to suit your specific requirements. These decorators will, 
unless otherwise specified, automatically initiate an OAuth flow if unauthenticated access it attempted.

At present, asfquart features the following restrictive decorators:

- `asfquart.auth.Requirements.committer`: User must be a committer of any project to access
- `asfquart.auth.Requirements.member`: User must be a member of the foundation to access
- `asfquart.auth.Requirements.chair`: User must be a chair or one or more projects
- `asfquart.auth.Requirements.mfa_enabled`: User must be logged in using a method that requires multi-factor authentication

The example below shows how to cordon off specific end-points to certain groups of users:

~~~python
import asfquart
from asfquart.auth import Requirements as R
APP = asfquart.APP
 
# URL that requires some sort of ASF auth (oauth, ldap)
@APP.route("/foo")
@asfquart.auth.require  # Bare decorator means just require a valid session
async def view_that_requires_auth():
   pass
 
# URL that requires 2FA (implies oauth since ldap doesn't have 2fa)
@APP.route("/foo2fa")
@asfquart.auth.require({R.mfa_enabled})
async def view_that_requires_2fa_auth():
   pass
 
# URL that requires a certain org role (2FA implied??)
@APP.route("/foorole")
@asfquart.auth.require({R.member})
async def view_that_requires_member_role():
   pass
~~~

~~~
