#!/usr/bin/env python3

"""ASFQuart - Base application/event-loop module.

USAGE:

  main.py:
    import asfquart
    APP = asfquart.construct('selfserve')

  anywhere else:
    import asfquart
    APP = asfquart.APP


Quart.app defines a "name" property which can be used as an APP "ID"
(eg. discriminator for cookies). While most Quart apps use the module
name for this (and internally Quart calls this .import_name), it can
be anything and the .name property treats it as arbitrary.
"""

import asyncio
import collections.abc
import logging
import os
import pathlib
import re
import secrets
import signal
import stat
import sys
import typing

import asfpy.twatcher
import easydict
import ezt
import hypercorn.utils
import quart  # implies .app
import quart.utils
import watchfiles
import yaml

from . import utils

try:
    ExceptionGroup  # pyright: ignore[reportUnboundVariable, reportUnusedExpression] - tests for the builtin
except NameError:
    # This version does not have an ExceptionGroup (introduced in
    # Python 3.11). Somebody (hypercorn) might be using a backport
    # of it from the "exceptiongroup" package. We'll catch that
    # instead. Note that packages designed for less than 3.11
    # won't be throwing ExceptionGroup (of any form) at all, which
    # means our catching it will be a no-op.
    if sys.version_info < (3, 11):
        from exceptiongroup import ExceptionGroup  # pyright: ignore[reportMissingImports] - Python 3.10 only

LOGGER = logging.getLogger(__name__)

_P = typing.ParamSpec("_P")
_R = typing.TypeVar("_R")
SECRETS_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600, read/write for this user only
SECRETS_FILE_UMASK = 0o777 ^ SECRETS_FILE_MODE  # Prevents existing umask from mangling the mode
CONFIG_FNAME = "config.yaml"
TOKEN_FNAME = "apptoken.txt"  # noqa: S105 - a file name, not a secret

# A handler for bearer tokens, sync or async: it is given the token, and returns the session
# data for it, or None. See docs/sessions.md.
TokenHandler = typing.Callable[[str], dict[str, typing.Any] | typing.Awaitable[dict[str, typing.Any] | None] | None]

# The shape of an ASF user id: lower case letters, digits, hyphens and underscores, starting with a
# letter, and at least two characters. This is the rule of AsfUid in atr/models/safe.py of
# apache/tooling-trusted-releases, except that AsfUid asks for three characters, and there are ASF
# users whose id has two.
#
# This is the one place where the rule is written. It is used under two more names, for the two
# places a user id comes into asfquart from outside: generics.OAUTH_UID_RE (the OAuth provider's
# response) and ldap.VALID_UID_RE (the username of HTTP Basic authentication). Change the rule
# here and it changes for both. An app that needs another rule for one of the two can assign a
# pattern of its own to that name.
#
# This rule, and the other checks that asfquart makes on its input, are listed in
# docs/input-validation.md.
ASF_UID_RE = re.compile(r"[a-z][a-z0-9_-]{1,}")


class ASFQuartException(Exception):  # noqa: N818 - public name
    """Global ASFQuart exception with a message and an error code, for the HTTP response."""

    def __init__(self, message: str = "An error occurred", errorcode: int = 500) -> None:
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message)


class QuartApp(quart.Quart):
    """Subclass of quart.Quart to include our specific features."""

    def __init__(
        self,
        app_id: str,
        /,
        app_dir: str | None = None,
        cfg_file: str | None = None,
        token_file: str | None = TOKEN_FNAME,
        *args: typing.Any,
        **kw: typing.Any,
    ) -> None:
        """Construct an ASFQuart web application.

        Arguments:
            app_id: The name of the application, usually ``__name__``.
            app_dir: Optional application directory, defaults to ``os.getcwd()`` if none is provided.
            cfg_file: Optional config file name, defaults to ``config.yaml`` if none is provided.
            token_file: Optional token file name, defaults to ``apptoken.txt``, when setting to None,
                        the app secret will not be persisted.
        """
        super().__init__(app_id, *args, **kw)

        self.app_id = app_id
        self.app_dir = pathlib.Path(app_dir or os.getcwd())
        self.cfg_path = self.app_dir / (cfg_file or CONFIG_FNAME)

        # Most apps will require a watcher for their EZT templates.
        self.tw = asfpy.twatcher.TemplateWatcher()
        self.add_runner(self.tw.watch_forever, name=f"TW:{app_id}")

        # use an easydict for config values
        self.cfg = easydict.EasyDict()

        # token handler callback for PATs - see docs/sessions.md
        self.token_handler: TokenHandler | None = None  # Default to no PAT handler available.
        # HTTP Basic authentication checks a password against LDAP, with no second factor, so an
        # app has to ask for it: construct(..., basic_auth=True). See docs/sessions.md.
        self.basic_auth = False
        # A session store, or None. Any, as a store is duck-typed and has methods of the app's own:
        # see docs/session-stores.md.
        self.sessions: typing.Any = None

        if token_file is not None:
            # Path.__truediv__ internally handles the case of absolute / relative path segments
            # if an anchored segment (i.e. absolute path) is provided, the segment will be returned as is.
            _token_filename = self.app_dir / token_file
        else:
            _token_filename = None

        self.token_path = _token_filename

        if _token_filename is None:
            self.secret_key = secrets.token_hex()
        else:
            # Read, or set and write, the application secret token for
            # session encryption. We prefer permanence for the session
            # encryption, but will fall back to a new secret if we
            # cannot write a permanent token to disk...with a warning!
            if os.path.isfile(_token_filename):  # Token file exists, try to read it
                # Test that permissions are as we want them, warn if not, but continue
                st = os.stat(_token_filename)
                file_mode = st.st_mode & 0o777
                if file_mode != SECRETS_FILE_MODE:
                    sys.stderr.write(
                        f"WARNING: Secrets file {_token_filename} has file mode {oct(file_mode)}, "
                        f"we were expecting {oct(SECRETS_FILE_MODE)}\n"
                    )
                with open(_token_filename, encoding="utf-8") as sfile:
                    self.secret_key = sfile.read()
                if not self.secret_key.strip():
                    # An empty file is not a secret: the app may have been stopped between creating
                    # the file and writing to it. Treat it as missing, and put a new secret in it.
                    LOGGER.warning(f"Secrets file {_token_filename} is empty; generating a new secret")
                    self.secret_key = secrets.token_hex()
                    try:
                        # Set the mode first, so that the secret is never in a file that others can
                        # read. If the mode cannot be set, the secret is not written to the file.
                        os.chmod(_token_filename, SECRETS_FILE_MODE)
                        with open(_token_filename, "w", encoding="utf-8") as sfile:
                            sfile.write(self.secret_key)
                    except OSError:
                        # Not only a lack of permission: a read-only file system or a full disk too
                        LOGGER.error(
                            f"Could not open {_token_filename} for writing. Session permanence cannot be guaranteed!"
                        )
            else:  # No token file yet, try to write, warn if we cannot
                self.secret_key = secrets.token_hex()
                ### TBD: throw the PermissionError once we stabilize how to locate
                ### the APP directory (which can be thrown off during testing)
                try:
                    # New secrets files should be created with chmod 600, to ensure that only
                    # the app has access to them. umask is recorded and changed during this, to
                    # ensure we don't have umask overriding what we want to achieve.
                    umask_original = os.umask(SECRETS_FILE_UMASK)  # Set new umask, log the old one
                    try:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        fd = os.open(_token_filename, flags=flags, mode=SECRETS_FILE_MODE)
                    finally:
                        os.umask(umask_original)  # reset umask to the original setting
                    with open(fd, "w", encoding="utf-8") as sfile:
                        sfile.write(self.secret_key)
                except OSError:
                    # Not only a lack of permission: a read-only file system or a full disk too
                    LOGGER.error(
                        f"Could not open {_token_filename} for writing. Session permanence cannot be guaranteed!"
                    )

    def runx(
        self,
        /,
        host: str = "0.0.0.0",  # noqa: S104 - the default has always been all interfaces
        port: int | None = None,
        debug: bool = True,
        loop: asyncio.AbstractEventLoop | None = None,
        certfile: str | None = None,
        keyfile: str | None = None,
        extra_files: collections.abc.Set[str | pathlib.Path] = frozenset(),  # OK, because immutable
    ) -> None:
        """Extended version of Quart.run()

        LOOP is the loop this app should run within. One will be constructed,
        if this is not provided.

        EXTRA_FILES is a set of files (### relative to?) that should be
        watched for changes. If a change occurs, the app will be reloaded.
        """

        # Default PORT is None, but it must be explicitly specified.
        if not port:
            raise ValueError("The port must be specified.")

        # NOTE: much of the code below is direct from quart/app.py:Quart.run()
        # This local "copy" is to deal with the custom watcher/reloader.

        if loop is None:
            loop = asyncio.new_event_loop()
            loop.set_debug(debug)

            asyncio.set_event_loop(loop)

        # Create a factory for a trigger that watches for exceptions.
        trigger = self.factory_trigger(loop, extra_files)

        # Construct a task to run the app.
        task = self.run_task(
            host,
            port,
            debug,
            certfile=certfile,
            keyfile=keyfile,
            shutdown_trigger=trigger,
        )

        # If certfile is None then https.
        protocol = "https" if certfile is not None else "http"

        ### LOG/print some info about the app starting?
        print(f' * Serving Quart app "{self.app_id}"')
        print(f" * Debug mode: {self.debug}")
        print(" * Using reloader: CUSTOM")
        print(f" * Running on {protocol}://{host}:{port}")
        print(" * ... CTRL + C to quit")

        # Ready! Start running the app.
        self.run_forever(loop, task)
        # Being here, means graceful exit.

    def factory_trigger(
        self, loop: asyncio.AbstractEventLoop, extra_files: collections.abc.Set[str | pathlib.Path] = frozenset()
    ) -> typing.Callable[[], typing.Coroutine[typing.Any, typing.Any, None]]:
        """Factory for an AWAITABLE that handles special exceptions.

        The LOOP normally ignores all signals. This method will make the
        loop catch SIGTERM/SIGINT, then set an Event to raise an exception
        for a clean exit.

        This will also observe files for changes, and signal the loop
        to reload the application.
        """

        # Note: Quart.run() allows for optional signal handlers. We do not.

        shutdown_event = asyncio.Event()

        def _shutdown_handler(*_: object) -> None:
            shutdown_event.set()

        loop.add_signal_handler(signal.SIGTERM, _shutdown_handler)
        loop.add_signal_handler(signal.SIGINT, _shutdown_handler)

        async def shutdown_wait() -> typing.NoReturn:
            "Log a nice message when we're signalled to shut down."
            await shutdown_event.wait()
            LOGGER.info("SHUTDOWN: Performing graceful exit...")
            gathered.cancel()
            raise hypercorn.utils.ShutdownError()

        restart_event = asyncio.Event()

        def _restart_handler(*_: object) -> None:
            restart_event.set()

        loop.add_signal_handler(signal.SIGUSR2, _restart_handler)

        async def restart_wait() -> typing.NoReturn:
            "Log a nice message when we're signalled to restart."
            await restart_event.wait()
            LOGGER.info("RESTART: Performing process restart...")
            gathered.cancel()
            raise quart.utils.MustReloadError()

        # Normally, for the SHUTDOWN_TRIGGER, it simply completes and
        # returns (eg. waiting on an event) as it gets wrapped into
        # hypercorn.utils.raise_shutdown() to raise ShutdownError.
        #
        # We are gathering three tasks, each running forever until its
        # condition raises an exception.
        #
        # .watch() will raise MustReloadError
        # shutdown_wait() will raise ShutdownError
        # restart_wait() will raise MustReloadError
        t1 = loop.create_task(self.watch(extra_files), name=f"Watch:{self.app_id}")
        t2 = loop.create_task(shutdown_wait(), name=f"Shutdown:{self.app_id}")
        t3 = loop.create_task(restart_wait(), name=f"Restart:{self.app_id}")
        aw = asyncio.gather(t1, t2, t3)

        gathered = utils.CancellableTask(aw, loop=loop, name=f"Trigger:{self.app_id}")

        async def await_gathered() -> None:
            await gathered.task

        return await_gathered  # factory to create an awaitable (coro)

    async def watch(self, extra_files: collections.abc.Set[str | pathlib.Path] = frozenset()) -> None:
        "Watch all known .py files, plus some extra files (eg. configs)."

        py_files = set(getattr(m, "__file__", None) for m in sys.modules.values())
        py_files.remove(None)  # the built-in modules

        if os.path.isfile(self.cfg_path):  # noqa: ASYNC240 - one local check, when the watcher starts
            cfg_files = {self.cfg_path}
        else:
            cfg_files = set()

        watched_files = py_files | cfg_files | extra_files

        # quiet down the watchfiles logger
        logging.getLogger("watchfiles.main").setLevel(logging.INFO)

        async for changes in watchfiles.awatch(*watched_files):  # pyright: ignore[reportArgumentType] - None was removed above
            for event in changes:
                if (
                    event[0] == watchfiles.Change.modified
                    or event[0] == watchfiles.Change.deleted
                    or event[0] == watchfiles.Change.added
                ):
                    LOGGER.info(f"File changed: {event[1]}")
                    raise quart.utils.MustReloadError
        # NOTREACHED

    def run_forever(self, loop: asyncio.AbstractEventLoop, task: typing.Awaitable[object]) -> None:
        "Run the application until exit, then cleanly shut down."

        # Note: this logic is copied from quart/app.py
        reload_ = False
        try:
            loop.run_until_complete(task)
        except quart.utils.MustReloadError:
            reload_ = True
            LOGGER.debug("FOUND: MustReloadError")
        except ExceptionGroup as e:  # pyright: ignore[reportPossiblyUnboundVariable] - the builtin or the backport
            reload_ = e.subgroup(quart.utils.MustReloadError) is not None
            LOGGER.debug(f"FOUND: ExceptionGroup, reload_={reload_}")
        finally:
            try:
                quart.app._cancel_all_tasks(loop)  # pylint: disable=protected-access
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.set_event_loop(None)
                loop.close()
        if reload_:
            quart.utils.restart()

    def load_template(self, tpath: str | os.PathLike[str], base_format: str = ezt.FORMAT_HTML) -> ezt.Template:
        # Use str() to avoid passing Path instances.
        return self.tw.load_template(str(self.app_dir / tpath), base_format=base_format)

    def use_template(
        self,
        path_or_T: str | os.PathLike[str] | ezt.Template,  # noqa: N803 - public argument name
        base_format: str = ezt.FORMAT_HTML,
    ) -> typing.Callable[
        [typing.Callable[_P, typing.Awaitable[_R]]],
        typing.Callable[_P, typing.Coroutine[typing.Any, typing.Any, _R | str]],
    ]:
        # Decorator to use a template, specified by path or provided.

        if isinstance(path_or_T, ezt.Template):
            return utils.use_template(path_or_T)

        return utils.use_template(self.load_template(path_or_T, base_format))

    def add_runner(self, func: typing.Callable[[], typing.Awaitable[object]], name: str | None = None) -> None:
        "Add a long-running task, with cancellation/cleanup."

        # NOTES:
        #
        # We take advantage of the WHILE_SERVING mechanism that uses a
        # generator to manage the lifecycle of a task. We create/schedule
        # a task when the app starts up, then yield back to the framework.
        # Control returns when the app is shutting down, and we can cleanly
        # cancel the long-running task.
        #
        # Contrast this with APP.background_tasks. Each task placed into
        # that set must monitor APP.shutdown_event to know when the task
        # should exit (or an external mechanism observing that event must
        # cancel the task). The coordination becomes more difficult, and
        # must be handled by the application logic. The WHILE_SERVING
        # mechanism used here places no demands upon the caller to manage
        # the lifecycle of the long-running task.
        #
        # Further note: should a task be placed into APP.background_tasks,
        # it will be waited on to exit at shutdown time. If the task is
        # not watching APP.shutdown_event, and does not complete, finish,
        # or cancel within a timeout period (default is 5 seconds), then
        # that background task is canceled. That is an unstructured
        # completion/cancellation mechanism and introduces a delay during
        # the shutdown process.

        @self.while_serving
        async def perform_runner() -> typing.AsyncGenerator[None, None]:
            ctask = utils.CancellableTask(func(), name=name)
            # print('RUNNER STARTED:', ctask.task)

            yield  # back to serving

            # print('RUNNER STOPPING:', ctask.task)
            ctask.cancel()


def construct(
    name: str,
    /,
    app_dir: str | None = None,
    cfg_file: str | None = None,
    token_file: str | None = TOKEN_FNAME,
    oauth: bool | str = True,
    force_login: bool = True,
    *args: typing.Any,
    basic_auth: bool = False,
    **kw: typing.Any,
) -> QuartApp:
    """Construct an ASFQuart web application.

    Arguments:
        name: The name of the application, usually ``__name__``.
        app_dir: Optional application directory, defaults to ``os.getcwd()`` if none is provided.
        cfg_file: Optional config file name, defaults to ``config.yaml`` if none is provided.
        token_file: Optional token file name, defaults to ``apptoken.txt``, when setting to None,
            the app secret will not be persisted.
        oauth: Optional, configure OAuth endpoint, defaults to ``true``, to use a different
            oauth URI than the default ``/auth``, specify the URI in the oauth argument,
            for instance: asfquart.construct("myapp", oauth="/session").
        force_login: Optional, enforces redirect to the oauth provider when a user
            accesses a restricted page, defaults to ``true``.
        basic_auth: Optional, enables HTTP Basic authentication via LDAP, defaults to ``false``.
            It accepts a user's ASF password with no second factor, so turn it on only for an
            app that needs it. When off, an ``Authorization: Basic`` header is answered with a 401.
            It needs the LDAP libraries (the ``aioldap`` extra): without them, ``basic_auth=True``
            raises a ``RuntimeError``.
    """

    # By default, we will set up OAuth and force login redirect on auth failure
    # This can be turned off by setting oauth=False in the construct call.
    # To use a different oauth URI than the default /auth, specify the URI
    # in the oauth argument, for instance: asfquart.construct("myapp", oauth="/session")
    setup_oauth = oauth
    force_auth_redirect = force_login and setup_oauth

    if basic_auth:
        # Fail now, and not at the first request with a Basic header: without the LDAP libraries
        # the app could not do what it was asked to, and nobody would be told.
        from . import ldap  # here, as ldap imports this module

        if not ldap.LDAP_SUPPORTED:
            raise RuntimeError(
                "basic_auth=True needs the LDAP libraries, which are not installed."
                ' Install asfquart with the aioldap extra ("asfquart[aioldap]"), or leave basic_auth off.'
            )
        # Now, before anything in the application has used the LDAP library, which reads it once
        ldap.set_network_timeout()

    app = QuartApp(name, app_dir, cfg_file, token_file, *args, **kw)
    app.basic_auth = basic_auth

    @app.errorhandler(ASFQuartException)  # ASFQuart exception handler
    async def handle_exception(error: ASFQuartException) -> quart.Response:
        # If an error is thrown before the request body has been consumed, eat it quietly.
        if not quart.request.body._complete.is_set():  # pylint: disable=protected-access
            async for _data in quart.request.body:
                pass
        return quart.Response(status=error.errorcode, response=error.message, content_type="text/plain; charset=utf-8")

    # try to load the config information from app.cfg_path
    if os.path.isfile(app.cfg_path):
        app.cfg.update(yaml.safe_load(open(app.cfg_path, encoding="utf-8")))

    # Provide our standard filename argument converter.
    import asfquart.utils

    # Sane defaults for cookies: SameSite=Strict; Secure; HttpOnly
    # The __Host- prefix makes a browser refuse the cookie unless it is Secure, has Path=/, and
    # has no Domain, so that no other host of the same site can give the browser a session cookie
    # for this app. See "Cookie names" in docs/sessions.md.
    app.config["SESSION_COOKIE_NAME"] = "__Host-session"
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    app.url_map.converters["filename"] = asfquart.utils.FilenameConverter

    # Set up oauth and login redirects if needed
    if setup_oauth:
        import asfquart.generics

        # Figure out the OAuth URI we want to use.
        oauth_uri = setup_oauth if isinstance(setup_oauth, str) else asfquart.generics.DEFAULT_OAUTH_URI
        asfquart.generics.setup_oauth(app, uri=oauth_uri)
        if force_auth_redirect:
            asfquart.generics.enforce_login(app, redirect_uri=oauth_uri)

    # Now stash this into the package module, for later pick-up.
    asfquart.APP = app

    return app
