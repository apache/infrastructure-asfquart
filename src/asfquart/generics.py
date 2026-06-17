#!/usr/bin/env python3
"""Generic endpoints for ASFQuart"""

import jwt
from jwt import PyJWKClient
import secrets
import urllib
import urllib.parse
import time

import quart
import aiohttp

import asfquart  # implies .session


# These are the ASF OAuth URLs for init and verification. Used for setup_oauth()
OAUTH_URL_INIT = "https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s"
OAUTH_URL_CALLBACK = "https://oauth.apache.org/token-oidc?code=%s"

# Enforce that the callback to the relying party will be https
OAUTH_ENFORCE_HTTPS = True

# Options for full OAuth2 validation
OAUTH_CLIENT_ID = None
OAUTH_CLIENT_SECRET = None
OAUTH_URL_JWKS = None
OAUTH_ISSUER = None

DEFAULT_OAUTH_URI = "/auth"

def setup_oauth(app, uri=DEFAULT_OAUTH_URI, workflow_timeout: int = 900):
    """Sets up a generic ASF OAuth endpoint for the given app. The default URI is /auth, and the
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

    @app.route(uri, methods=["GET", "POST"])
    async def oauth_endpoint():
        # lightweight CSRF protection.
        if quart.request.method == "POST":
            if quart.request.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "same-site"):
                return quart.Response(
                    status=403,
                    response="CSRF Protection\n",
                    content_type="text/plain; charset=utf-8"
                )
        # Init oauth login
        login_uri = quart.request.args.get("login")
        logout_uri = quart.request.args.get("logout")
        if login_uri or quart.request.query_string == b"login":
            if login_uri and ((not login_uri.startswith("/")) or login_uri.startswith("//")):
                return quart.Response(
                    status=400,
                    response="Invalid redirect URI.\n",
                    content_type="text/plain; charset=utf-8"
                )
            state = secrets.token_hex(16)
            callback_host = quart.request.host_url
            if OAUTH_ENFORCE_HTTPS:
                callback_host = callback_host.replace("http://", "https://")
            if OAUTH_CLIENT_ID:
                callback_url = urllib.parse.urljoin(
                    callback_host,
                    f"{uri}",
                )
            else:
                callback_url = urllib.parse.urljoin(  # NOTE: the uri MUST start with a single forward slash!
                    callback_host,
                    f"{uri}?state={state}",
                )
            # Save the time we initialized this state and the optional login redirect URI
            pending_states[state] = [time.time(), login_uri, callback_url]
            redirect_url = OAUTH_URL_INIT % (state, urllib.parse.quote(callback_url))
            if OAUTH_CLIENT_ID:
                redirect_url = redirect_url + "&response_type=code&scope=openid&client_id=" + OAUTH_CLIENT_ID
            return quart.redirect(redirect_url)

        # Log out
        elif logout_uri or quart.request.query_string == b"logout":
            asfquart.session.clear()
            if logout_uri and ((not logout_uri.startswith("/")) or logout_uri.startswith("//")):
                response = quart.Response(
                    status=400,
                    response="Invalid redirect URI.\n",
                    content_type="text/plain; charset=utf-8"
                )
            elif logout_uri:  # if called with /auth=logout=/foo, redirect to /foo
                response = quart.redirect(logout_uri)
            elif quart.request.method == "POST":
                response = quart.Response(status=204)
            else:
                response = quart.Response(
                    status=200,
                    response="Client session removed, goodbye!\n",
                    content_type="text/plain; charset=utf-8"
                )
            response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
            return response
        else:
            code = quart.request.args.get("code")
            state = quart.request.args.get("state")
            if code and state:  # Callback from oauth, complete flow.
                # grab the state data before using it
                # This ensures it can only be used once
                state_data = pending_states.pop(state, None)  # safe pop
                if state_data is None or state_data[0] < (time.time() - workflow_timeout):
                    return quart.Response(
                        status=403,
                        response=f"Invalid or expired OAuth state provided. OAuth workflows must be completed within {workflow_timeout} seconds.\n",
                        content_type="text/plain; charset=utf-8"
                    )
                post_login_redirect_uri = state_data[1]
                original_redirect_uri = state_data[2]
                ct = aiohttp.client.ClientTimeout(sock_read=15)
                async with aiohttp.client.ClientSession(timeout=ct) as session:
                    if OAUTH_CLIENT_SECRET:
                        auth = aiohttp.BasicAuth(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET)
                        data = {
                            'grant_type': "authorization_code",
                            'redirect_uri': original_redirect_uri,
                            'code': code
                        }
                        rv = await session.post(OAUTH_URL_CALLBACK, auth=auth, data=data)
                    else:
                        rv = await session.get(OAUTH_URL_CALLBACK % code)
                    if rv.status != 200:
                        # TODO there is likely useful diagnostic
                        # information in the response body, where
                        # do we log that?
                        return quart.Response(
                            status=403,
                            response="OAuth authentication failed.\n",
                            content_type="text/plain; charset=utf-8"
                        )

                    if OAUTH_CLIENT_SECRET:
                        token = await rv.json()
                        jwks_client = PyJWKClient(OAUTH_URL_JWKS)
                        id_token = token["id_token"]
                        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
                        oauth_data = jwt.decode(
                          id_token,
                          signing_key.key,
                          algorithms=["RS256"],
                          audience=OAUTH_CLIENT_ID,
                          issuer=OAUTH_ISSUER,
                        )
                    else:
                        oauth_data = await rv.json()

                    asfquart.session.write(oauth_data)
                if post_login_redirect_uri:  # if called with /auth=login=/foo, redirect to /foo
                    # If SameSite is set, we cannot redirect with a 30x response, as that may invalidate the set-cookie
                    # instead, we issue a 200 Okay with a Refresh header, instructing the browser to immediately go
                    # someplace else. This counts as a samesite request.
                    return quart.Response(
                        status=200,
                        response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                        headers={"Refresh": f"0; url={post_login_redirect_uri}"},
                        content_type="text/plain; charset=utf-8"
                    )
                # Otherwise, just say hi
                return quart.Response(
                    status=200,
                    response=f"Successfully logged in! Welcome, {oauth_data['uid']}\n",
                    content_type="text/plain; charset=utf-8"
                )
            else:  # Just spit out existing session if it's there
                client_session = await asfquart.session.read()
                if isinstance(client_session, asfquart.session.ClientSession):
                    return client_session
                return quart.Response(
                    status=404,
                    response="No active session found.\n",
                    content_type="text/plain; charset=utf-8"
                )


def enforce_login(app, redirect_uri=DEFAULT_OAUTH_URI):
    """Enforces redirect to the auth provider (if enabled) when a client tries to access a restricted page
    without being logged in. Only redirects if there is no active user session. On success, the client
    is redirected back to the origin page that was restricted. If it is still restricted, the client
    will instead see an error message."""

    @app.errorhandler(asfquart.auth.AuthenticationFailed)
    async def auth_redirect(error):
        # If we have no client session (and X-No-Redirect is not set), redirect to auth flow
        if (
            "x-no-redirect" not in quart.request.headers
            and not quart.request.authorization
            and not await asfquart.session.read()
        ):
            # The werkzeug.sansio.request.full_path property returns:
            # f"{self.path}?{self.query_string.decode()}"
            # Therefore it contains a "?" even if there is no query string
            full_path = quart.request.full_path
            # Strip the trailing "?" when the query string is empty
            if full_path.endswith("?"):
                parsed = urllib.parse.urlsplit(full_path)
                if not parsed.query:
                    # The query string is empty
                    full_path = full_path[:-1]
            quoted_path = urllib.parse.quote(full_path)
            return quart.redirect(f"{redirect_uri}?login={quoted_path}")
        # If we have a session, but still no access, just say so in plain text.
        return quart.Response(
            status=error.errorcode,
            response=error.message,
            content_type="text/plain; charset=utf-8"
        )
