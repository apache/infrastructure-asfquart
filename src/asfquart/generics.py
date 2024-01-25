#!/usr/bin/env python3
"""Generic endpoints for ASFQuart"""

import quart
import uuid
import urllib
import aiohttp
import time


# These are the ASF OAuth URLs for init and verification. Used for setup_oauth()
OAUTH_URL_INIT = "https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s"
OAUTH_URL_CALLBACK = "https://oauth.apache.org/token-oidc?code=%s"


def setup_oauth(uri="/auth", workflow_timeout: int = 900):
    """ "Sets up a generic ASF OAuth endpoint. The default URI is /auth, and the
    default workflow timeout is 900 seconds (15 min), within which the OAuth login must
    be completed. The OAuth endpoint handles everything related to logging in and out via OAuth,
    and has the following actions:

    - /auth?login  - Initializes an OAuth login
    - /auth?login=/foo - Same as above, but redirects to /foo on successful login
    - /auth?logout - Clears a user session, logging them out
    - /auth  - Shows the user's credentials if logged in, 404 otherwise.

    This generic route expects the Host: header of the request to be accurate, which means setting
    "ProxyPreserveHost On" in your httpd config if proxying.
    """

    pending_states = {}  # keeps track of pending states and their expiry
    import asfquart  # We import at this point to grab the APP pointer

    @asfquart.APP.route(uri)
    async def oauth_endpoint():
        # Init oauth login
        login_uri = quart.request.args.get("login")
        logout_uri = quart.request.args.get("logout")
        if login_uri or quart.request.query_string == b"login":
            state = str(uuid.uuid4())
            # Save the time we initialized this state and the optional login redirect URI
            pending_states[state] = [time.time(), login_uri]
            callback_host = quart.request.host_url.replace("http://", "https://")  # Enforce HTTPS
            callback_url = urllib.parse.urljoin(  # NOTE: the uri MUST start with a single forward slash!
                callback_host,
                f"{uri}?state={state}",
            )
            redirect_url = OAUTH_URL_INIT % (state, urllib.parse.quote(callback_url))
            headers = {
                "Location": redirect_url,
            }
            return quart.Response(status=302, response="Redirecting...", headers=headers)

        # Log out
        elif logout_uri or quart.request.query_string == b"logout":
            asfquart.session.clear()
            if logout_uri:  # if called with /auth=logout=/foo, redirect to /foo
                headers = {
                    "Location": logout_uri,
                }
                return quart.Response(status=302, response="Redirecting...", headers=headers)
            return quart.Response(
                status=200,
                response=f"Client session removed, goodbye!\n",
            )
        else:
            code = quart.request.args.get("code")
            state = quart.request.args.get("state")
            if code and state:  # Callback from oauth, complete flow.
                if state not in pending_states or pending_states[state][0] < (time.time() - workflow_timeout):
                    pending_states.pop(state, None)  # safe pop
                    return quart.Response(
                        status=403,
                        response=f"Invalid or expired OAuth state provided. OAuth workflows must be completed within {workflow_timeout} seconds.\n",
                    )
                redirect_uri = pending_states[state][1]
                pending_states.pop(
                    state
                )  # Pop the state from pending. We do this straight away to avoid timing attacks
                ct = aiohttp.client.ClientTimeout(sock_read=15)
                async with aiohttp.client.ClientSession(timeout=ct) as session:
                    rv = await session.get(OAUTH_URL_CALLBACK % code)
                    assert rv.status == 200, "Could not verify oauth response."
                    oauth_data = await rv.json()
                    asfquart.session.write(oauth_data)
                if redirect_uri:  # if called with /auth=login=/foo, redirect to /foo
                    headers = {
                        "Location": redirect_uri,
                    }
                    return quart.Response(status=302, response="Redirecting...", headers=headers)
                # Otherwise, just say hi
                return quart.Response(
                    status=200,
                    response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                )
            else:  # Just spit out existing session if it's there
                client_session = asfquart.session.read()
                if client_session and isinstance(client_session, dict):
                    return client_session
                return quart.Response(
                    status=404,
                    response=f"No active session found.\n",
                )