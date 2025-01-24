#!/usr/bin/env python3

import pathlib

import pytest
import asfquart

TEST_CONFIG_FILENAME = pathlib.Path(__file__).parent / "data/config.test.yaml"
times_loaded = 0


@pytest.mark.asyncio
@pytest.mark.config
async def test_config_static():
    """Tests static (one-time) configuration parsing in blocking and async mode"""

    @asfquart.config.static
    async def config_callback(yml: dict):
        assert yml, "Config YAML is empty!"
        assert isinstance(yml, dict), "Config YAML is not a dict!"

    # Async test
    await config_callback(TEST_CONFIG_FILENAME)
