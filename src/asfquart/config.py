#!/usr/bin/env python3
"""ASFQuart - Configuration readers"""
import signal
import asyncio
import yaml
import functools
import inspect
import os

from . import base

DEFAULT_CONFIG_FILENAME = "config.yaml"


async def _read_config(callback, config_filename):
    """Reads a YAML configuration and passes it to the callback"""
    config_as_dict = yaml.safe_load(open(config_filename))
    # Some configuration routines may require os to block while the configuration is applied, so
    # we will accept both sync and async callbacks.
    # If the callback is async, await it...
    if inspect.iscoroutinefunction(callback):
        await callback(config_as_dict)
    # Otherwise, just run it in blocking mode
    else:
        callback(config_as_dict)


def static(func):
    """Standard wrapper for a configuration parser. Reads config.yaml and passes it to the callback as a dict"""

    @functools.wraps(func)
    async def config_wrapper(config_filename=DEFAULT_CONFIG_FILENAME):
        await _read_config(func, config_filename)

    return config_wrapper


def dynamic(func):
    """Reloadable configuration parser. On startup, or when SIGUSR2 is intercepted, the configuration is reloaded and
    passed to the configuration callback function."""
    # If running test suite, the event loop needs to be reset
    if "PYTEST_CURRENT_TEST" in os.environ and base.loop.is_closed():
        base.loop = asyncio.get_event_loop()

    @functools.wraps(func)
    async def config_wrapper_dynamic(config_filename=DEFAULT_CONFIG_FILENAME):
        def new_task():
            return asyncio.create_task(_read_config(func, config_filename))

        # Add a signal handler for SIGUSR2
        base.loop.add_signal_handler(signal.SIGUSR2, new_task)
        # Read the config on first run
        await _read_config(func, config_filename)

    return config_wrapper_dynamic
