# Session handling

OAuth user sessions can be accessed through the `asfquart.session` component, and are encrypted 
to ensure authenticity.

The login and logout flow is automatically handled by asfquart, unless explicitly told not to, 
and sessions can be accessed and modified as needed:

~~~python

@asfquart.auth.require  # Implicitly require a valid (non-empty) session
async def endpoint_with_session():
   session = await asfquart.session.read()  # Read user session dict
   session["foobar"] = 42
   asfquart.session.write(session)  # Store our changes in the user session
~~~

Session timeouts can be handled by passing the `expiry_time` argument to the `read()` call:

~~~python
session = await asfquart.session.read(expiry_time=24*3600)  # Require a session that has been accessed in the past 24 hours.
assert session, "No session found or session expired"  # If too old or not found, read() returns None
~~~


