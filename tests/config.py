#!/usr/bin/env python3

import sys
sys.path.append(".")

import pytest
from src import asfquart
import signal
import asyncio
import pathlib

TEST_CONFIG_FILENAME = pathlib.Path(__file__).parent / "data/config.test.yaml"
times_loaded = 0


@pytest.mark.asyncio
@pytest.mark.config
async def test_config_static():
    """Tests static (one-time) configuration parsing in blocking and async mode"""

    @asfquart.config.static
    def config_callback(yml: dict):
        assert yml, "Config YAML is empty!"
        assert isinstance(yml, dict), "Config YAML is not a dict!"

    # Async test
    await config_callback(TEST_CONFIG_FILENAME)


@pytest.mark.asyncio
@pytest.mark.config
async def test_config_dynamic():
    """Tests static (one-time) configuration parsing in blocking and async mode"""
    global times_loaded

    @asfquart.config.dynamic
    async def config_callback(yml: dict):
        global times_loaded
        assert yml, "Config YAML is empty!"
        assert isinstance(yml, dict), "Config YAML is not a dict!"
        times_loaded += 1  # Track how many times we loaded the config

    # First run, on start
    await config_callback(TEST_CONFIG_FILENAME)

    # Send signals for three reloads...
    signal.raise_signal(signal.SIGUSR2)
    signal.raise_signal(signal.SIGUSR2)
    signal.raise_signal(signal.SIGUSR2)

    # Add a final task to ensure all our loops have completed
    last_task = asyncio.get_event_loop().create_task(asyncio.sleep(0))
    await asyncio.gather(last_task)
    assert (
        times_loaded == 4
    ), f"Dynamic configuration was scheduled to load four times, but was only loaded {dc.times_loaded}!"
