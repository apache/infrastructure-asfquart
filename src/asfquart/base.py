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

import sys
import asyncio
import pathlib
import secrets
import os
import logging
import signal

import asfpy.twatcher
import quart
import hypercorn.utils
import ezt
import asyncinotify

import __main__
from . import utils

LOGGER = logging.getLogger(__name__)
SECRETS_FILE_MODE = 0o600  # Expected permissions for secrets file (r/w for app only)


class ASFQuartException(Exception):
    """Global ASFQuart exception with a message and an error code, for the HTTP response."""

    def __init__(self, message: str = "An error occurred", errorcode: int = 500):
        self.message = message
        self.errorcode = errorcode
        super().__init__(self.message)


class QuartApp(quart.Quart):
    """Subclass of quart.Quart to include our specific features."""

    def __init__(self, app_id, *args, **kw):
        super().__init__(app_id, *args, **kw)

        # Locate the app dir as best we can. This is used for app ID
        # and token filepath generation
        # TODO: hypercorn does not have a __file__ variable available,
        # so we are forced to fall back to CWD. Maybe have an optional arg
        # for setting the app dir?
        if hasattr(__main__, "__file__"):
            self.app_dir = pathlib.Path(__main__.__file__).parent
        else:  # No __file__, probably hypercorn, fall back to cwd for now
            self.app_dir = pathlib.Path(os.getcwd())
        self.app_id = app_id

        # Most apps will require a watcher for their EZT templates.
        self.tw = asfpy.twatcher.TemplateWatcher()
        self.add_runner(self.tw.watch_forever, name=f"TW:{app_id}")

        # Read, or set and write, the application secret token for
        # session encryption. We prefer permanence for the session
        # encryption, but will fall back to a new secret if we
        # cannot write a permanent token to disk...with a warning!
        _token_filename = self.app_dir / "apptoken.txt"

        if os.path.isfile(_token_filename):  # Token file exists, try to read it
            # Test that permissions are as we want them, warn if not, but continue
            st = os.stat(_token_filename)
            file_mode = st.st_mode & 0o777
            if file_mode != SECRETS_FILE_MODE:
                sys.stderr.write(
                    f"WARNING: Secrets file {_token_filename} has file mode {oct(file_mode)}, we were expecting {oct(SECRETS_FILE_MODE)}\n"
                )
            self.secret_key = open(_token_filename).read()
        else:  # No token file yet, try to write, warn if we cannot
            self.secret_key = secrets.token_hex()
            ### TBD: throw the PermissionError once we stabilize how to locate
            ### the APP directory (which can be thrown off during testing)
            try:
                # New secrets files should be created with chmod 600, to ensure that only
                # the app has access to them. For existing (or modified) secrets, we will
                # keep permissions as is for now. TODO: Perhaps warn about file permissions?
                fd = os.open(
                    path=_token_filename, flags=(os.O_WRONLY | os.O_CREAT | os.O_TRUNC), mode=SECRETS_FILE_MODE
                )
                open(fd, "w").write(self.secret_key)
            except PermissionError:
                LOGGER.error(f"Could not open {_token_filename} for writing. Session permanence cannot be guaranteed!")

    def runx(self, /,
             host="0.0.0.0", port=None,
             debug=True, loop=None,
             extra_files=frozenset(), # OK, because immutable
             ):
        """Extended version of Quart.run()

        LOOP is the loop this app should run within. One will be constructed,
        if this is not provided.

        EXTRA_FILES is a set of files (### relative to?) that should be
        watched for changes. If a change occurs, the app will be reloaded.
        """

        # Default PORT is None, but it must be explicitly specified.
        assert port, "The port must be specified."

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
            shutdown_trigger=trigger,
        )

        ### LOG/print some info about the app starting?
        print(f' * Serving Quart app "{self.app_id}"')
        print(f" * Debug mode: {self.debug}")
        print(" * Using reloader: CUSTOM")
        print(f" * Running on http://{host}:{port}")
        print(" * ... CTRL + C to quit")

        # Ready! Start running the app.
        self.run_forever(loop, task)
        # Being here, means graceful exit.

    @staticmethod
    def factory_trigger(loop, extra_files):
        """Factory for an AWAITABLE that handles special exceptions.

        The LOOP normally ignores all signals. This method will make the
        loop catch SIGTERM/SIGINT, then set an Event to raise an exception
        for a clean exit.

        This will also observe files for changes, and signal the loop
        to reload the application.
        """

        # Note: Quart.run() allows for optional signal handlers. We do not.

        shutdown_event = asyncio.Event()
        def _shutdown_handler(*_) -> None:
            shutdown_event.set()
        loop.add_signal_handler(signal.SIGTERM, _shutdown_handler)
        loop.add_signal_handler(signal.SIGINT, _shutdown_handler)
        async def shutdown_wait():
            "Log a nice message when we're signalled to shut down."
            await shutdown_event.wait()
            LOGGER.info('SHUTDOWN: Performing graceful exit...')
            raise hypercorn.utils.ShutdownError()

        restart_event = asyncio.Event()
        def _restart_handler(*_) -> None:
            restart_event.set()
        loop.add_signal_handler(signal.SIGUSR2, _restart_handler)
        async def restart_wait():
            "Log a nice message when we're signalled to restart."
            await restart_event.wait()
            LOGGER.info('RESTART: Performing process restart...')
            raise hypercorn.utils.MustReloadError()

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
        t1 = loop.create_task(QuartApp.watch(extra_files))
        t2 = loop.create_task(shutdown_wait())
        t3 = loop.create_task(restart_wait())

        async def gather_conditions():
            await asyncio.gather(t1, t2, t3)

        return gather_conditions  # factory to create an awaitable (coro)

    @staticmethod
    async def watch(extra_files):
        "Watch all known .py files, plus some extra files (eg. configs)."

        py_files = set(getattr(m, "__file__", None) for m in sys.modules.values())
        py_files.remove(None)  # the built-in modules

        inotify = asyncinotify.Inotify()
        for path in py_files | extra_files:
            inotify.add_watch(
                path,
                asyncinotify.Mask.MODIFY  # file is modified
                | asyncinotify.Mask.DELETE_SELF  # file was deleted
                | asyncinotify.Mask.MOVE_SELF  # file moved away
                | asyncinotify.Mask.MASK_ADD,  # add all above to any existing watches
            )

        with inotify:
            async for event in inotify:
                LOGGER.info(f"File changed: {event.path}")
                raise hypercorn.utils.MustReloadError
        # NOTREACHED

    @staticmethod
    def run_forever(loop, task):
        "Run the application until exit, then cleanly shut down."

        # Note: this logic is close to quart/app.py but we do not
        # handle reload/restart here. That is handled by hypercorn
        # in the task created by .run_task() (with exceptions thrown
        # by our complex trigger).
        try:
            loop.run_until_complete(task)
        finally:
            try:
                quart.app._cancel_all_tasks(loop) # pylint: disable=protected-access
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.set_event_loop(None)
                loop.close()

    def load_template(self, tpath, base_format=ezt.FORMAT_HTML):
        # Use str() to avoid passing Path instances.
        return self.tw.load_template(str(self.app_dir / tpath), base_format=base_format)

    def use_template(self, path_or_T, base_format=ezt.FORMAT_HTML):
        # Decorator to use a template, specified by path or provided.

        if isinstance(path_or_T, ezt.Template):
            return utils.use_template(path_or_T)

        return utils.use_template(self.load_template(path_or_T, base_format))

    def add_runner(self, func, name=None):
        "Add a long-running task, with cancellation/cleanup."

        @self.while_serving
        async def perform_runner():
            ctask = utils.CancellableTask(func(), name=name)
            #print('RUNNER STARTED:', ctask.task)
            self.background_tasks.add(ctask.task)

            yield  # back to serving

            #print('RUNNER STOPPING:', ctask.task)
            ctask.cancel()


def construct(name, *args, **kw):
    ### add/alter/update ARGS and KW for our specific preferences

    # By default, we will set up OAuth and force login redirect on auth failure
    # This can be turned off by setting oauth=False in the construct call.
    # To use a different oauth URI than the default /auth, specify the URI
    # in the oauth argument, for instance: asfquart.construct("myapp", oauth="/session")
    # Pop the arguments from KW, as the parent class doesn't understand them.
    setup_oauth = kw.pop("oauth", True)
    # Note: order is important, as we want the .pop() to always execute.
    force_auth_redirect = kw.pop("force_login", True) and setup_oauth

    app = QuartApp(name, *args, **kw)

    @app.errorhandler(ASFQuartException)  # ASFQuart exception handler
    async def handle_exception(error):
        # If an error is thrown before the request body has been consumed, eat it quietly.
        if not quart.request.body._complete.is_set():  # pylint: disable=protected-access
            async for _data in quart.request.body:
                pass
        return quart.Response(status=error.errorcode, response=error.message)

    # Provide our standard filename argument converter.
    import asfquart.utils

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
