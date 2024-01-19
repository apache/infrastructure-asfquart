#!/usr/bin/env python3

import sys

sys.path.extend(
    (
        "src",
        "../src",
    )
)  # Depending on where unit tests are run from, path may differ

import pytest
import time
import quart
import asfquart
import asfquart.auth
from asfquart.auth import Requirements as R


@pytest.mark.asyncio
@pytest.mark.auth
async def test_auth():
    asfquart.construct("foobar")

    @asfquart.auth.require
    async def requires_session():
        pass

    # Test with no session, should fail
    quart.session = {}
    try:
        await requires_session()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message is asfquart.auth.ErrorMessages.NOT_LOGGED_IN

    # Test with session, should work.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar"}}
    await requires_session()


@pytest.mark.asyncio
@pytest.mark.auth
async def test_mfa_auth():
    """MFA tests"""

    asfquart.construct("foobar")

    @asfquart.auth.require(R.mfa_enabled)
    async def requires_mfa():
        pass

    # Test MFA with no session, should fail exactly like auth_required
    quart.session = {}
    try:
        await requires_mfa()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message is asfquart.auth.ErrorMessages.NOT_LOGGED_IN

    # Test with session without MFA, should fail.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar"}}
    try:
        await requires_mfa()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message is asfquart.auth.ErrorMessages.NO_MFA

    # Test with session with MFA, should work.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar", "mfa": True}}
    await requires_mfa()


@pytest.mark.asyncio
@pytest.mark.auth
async def test_role_auth():
    """Role tests"""
    asfquart.construct("foobar")

    # Set up some role tests
    @asfquart.auth.require  # no args implies any valid account
    async def test_committer_auth():
        pass

    @asfquart.auth.require(R.member)
    async def test_member_auth():
        pass

    @asfquart.auth.require({R.member, R.chair})
    async def test_member_and_chair_auth():
        pass

    @asfquart.auth.require(any_of={R.member, R.chair})
    async def test_member_or_chair_auth():
        pass

    # Test role with no session, should fail exactly like auth_required
    quart.session = {}
    try:
        await test_committer_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message is asfquart.auth.ErrorMessages.NOT_LOGGED_IN

    # Test with session , should work
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar"}}
    await test_committer_auth()

    # Test with a role we don't have, should fail
    try:
        await test_member_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message is asfquart.auth.ErrorMessages.NOT_MEMBER

    # Test with for both member and chair, while only being member. should pass on member check, fail on chair
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar", "isMember": True}}
    try:
        await test_member_and_chair_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message is asfquart.auth.ErrorMessages.NOT_CHAIR

    # Test for either member of chair, should work as we have chair (but not member)
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar", "isChair": True}}
    await test_member_or_chair_auth()

    # Test for both member and chair, when we are both. should work.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar", "isMember": True, "isChair": True}}
    await test_member_and_chair_auth()
