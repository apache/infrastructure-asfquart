#!/usr/bin/env python3
"""Tests for utils.py"""

import ezt
import pytest
import quart

import asfquart.utils


def _template(text):
    t = ezt.Template()
    t.parse(text)
    return t


@pytest.mark.utils
async def test_use_template_renders_data():
    """A handler's data dictionary is rendered through the template."""

    @asfquart.utils.use_template(_template("Hello [name]"))
    async def page():
        return {"name": "world"}

    assert await page() == "Hello world"


@pytest.mark.utils
async def test_use_template_passes_response_through():
    """A handler's Response (a redirect, say) is returned as it is, not rendered."""

    redirect = quart.Response("", status=302, headers={"Location": "/elsewhere"})

    @asfquart.utils.use_template(_template("Hello [name]"))
    async def page():
        return redirect

    assert await page() is redirect
