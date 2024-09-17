#!/usr/bin/env python3
"""ASFQuart - Status and Health Check Features"""

from . import base, session
import types
import typing
import asyncio
import enum
import easydict
import asfpy.whoami
import time
import aiohttp

# Default broadcast URL for health pushes
DEFAULT_BROADCAST_URL = "https://infra-reports.apache.org/api/health"

# This is who we are, for broadcast purposes
HOSTNAME = asfpy.whoami.whoami()

# Only perform app health broadcast if this is run on ASF hardware,
# which entails whoami() returning a hostname ending in ".apache.org"
PERFORM_BROADCAST = HOSTNAME.endswith(".apache.org")

ACCEPTED_DATA_TYPES = [str, int, float, dict, types.NoneType]
ADT_TXT = ",".join([str(t.__name__) for t in ACCEPTED_DATA_TYPES])


class Levels(enum.Enum):
    GREEN = 0  # Everything is in working order
    YELLOW = 1  # Low impact on service performance
    ORANGE = 2  # Severe impact on service performance
    RED = 3  # Service is NOT WORKING


class StatusReport:
    """A status update from a single health or status function"""

    def __init__(self, level: Levels, data: typing.Any = None):
        self.epoch = time.time()
        self.level = level
        # Data can be one of the following understood formats:
        # - a single numeric value (int or float)
        # - a single string value
        # - a dict with key/value pairs where the values can be either strings or numbers
        # - None, in which case there is no additional data available from this check
        if not any(isinstance(data, xtype) for xtype in ACCEPTED_DATA_TYPES):
            raise TypeError(f"Status data can only be one of: {ADT_TXT}")


class StatusCheck:
    """A single status check for the health monitoring."""

    def __init__(
        self,
        app: base.QuartApp,
        function: callable,
        name: str,
        description: str = None,
        required_status: bool = False,
        poll_for_status: bool = True,
    ):
        """Sets up a new status check. The `name` value corresponds with the slug the status will
        have in the report and the JSON objects. The `description` string can be any
        information you wish to use to describe this check. If required_status is True, this check
        must pass cleanly for the overall status to be green. If poll_for_status is True, requests for reading the
        service status will call this function and use the return value for its status update. If
        False, it is assumed that the function is a coroutine loop, and will be run continuously
        in the background, with asynchronous yields used for status updates."""
        self.app = app
        self.do_poll = poll_for_status
        self.name = name or "anonymous status check"
        self.description = description or f"Status check for {name}"
        self.required = required_status
        self.value = None
        self._function = function
        if asyncio.iscoroutinefunction(function):
            print("is async func!")
            if not self.do_poll:  # Loop! run it forever inside the app's task loop after startup
                app.add_runner(function(self))
        else:
            print("what do I know!!")

    @property
    async def status(self):
        if self.do_poll:
            self.value = await self._function()
        if not isinstance(self.value, StatusReport):
            pass  # Return bad juju here
        return self.value


class AppStatus:
    """A status controller for an asfquart app. Handles broadcasting of health as well as
    a status dashboard and json endpoint with various health and status information."""

    def __init__(self, app: base.QuartApp, app_url: str = None):
        assert isinstance(app, base.QuartApp), "AppStatus needs to be attached to an existing ASFQuart app class!"
        self.app = app

        # Our box hostname
        self.hostname = HOSTNAME
        # Our self-referential URL (iow where this app can be reached, in theory)
        self.url = isinstance(app_url, str) and app_url or f"https://{self.hostname}/"

        self._status_checks = []

    async def broadcast(self):
        # If we recognize this host as an internal ASF host, send off a broadcast ping to IRD for monitoring
        # TODO: Actually make the ping
        if PERFORM_BROADCAST and False:  # This won't run yet!
            ct = aiohttp.client.ClientTimeout(sock_read=15)
            try:
                async with aiohttp.client.ClientSession(timeout=ct) as session:
                    # Send the ping to IRD, announcing where we think we are
                    _rv = await session.post(DEFAULT_BROADCAST_URL, data={
                        "self": self.url,
                        "host": HOSTNAME,
                        "app": self.app.app_id,
                    })
            except aiohttp.ClientError as e:
                print(f"WARNING: Could not initiate health broadcast to {DEFAULT_BROADCAST_URL}: {e}")

    def add_status_check(self, function: callable, required=False):
        """Adds a new status check to the monitor. If `required` is True, this
        check will influence whether the overall status is green or not."""
        status_check = StatusCheck(
            self.app, function=function, name=function.__name__, required_status=required, poll_for_status=True
        )
        self._status_checks.append(status_check)
        return status_check

    async def status_response(self):
        """TBD: status as a json response...collate somehow"""
        pass
