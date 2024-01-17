#!/usr/bin/env python3

import sys
sys.path.extend(('src', '../src',))  # Depending on where unit tests are run from, path may differ

import pytest
import time
import quart
import asfquart
import asfquart.auth

@pytest.mark.asyncio
@pytest.mark.auth
async def test_auth():
    asfquart.construct("foobar")

    @asfquart.auth.auth_required
    async def test_auth():
        pass

    # Test with no session, should fail
    quart.session = {}
    try:
        await test_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message == "You must authenticate yourself before you can access this endpoint."

    # Test with session, should work.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar"}}
    await test_auth()


@pytest.mark.asyncio
@pytest.mark.auth
async def test_mfa_auth():
    """MFA tests"""

    asfquart.construct("foobar")
    @asfquart.auth.mfa_required
    async def test_mfa_auth():
        pass

    # Test MFA with no session, should fail exactly like auth_required
    quart.session = {}
    try:
        await test_mfa_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message == "You must authenticate yourself before you can access this endpoint."

    # Test with session without MFA, should fail.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar"}}
    try:
        await test_mfa_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message == "This endpoint can only be accessed through a multi-factor authenticated session."

    # Test with session with MFA, should work.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar", "mfa": True}}
    await test_mfa_auth()


@pytest.mark.asyncio
@pytest.mark.auth
async def test_role_auth():
    """Role tests"""

    asfquart.construct("foobar")

    # Set up some role tests
    @asfquart.auth.role_required(asfquart.auth.roles.committer)
    async def test_committer_auth():
        pass

    @asfquart.auth.role_required(asfquart.auth.roles.member)
    async def test_member_auth():
        pass

    @asfquart.auth.role_required(all_of=[asfquart.auth.roles.member, asfquart.auth.roles.chair])
    async def test_member_and_chair_auth():
        pass

    # Test role with no session, should fail exactly like auth_required
    quart.session = {}
    try:
        await test_committer_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message == "You must authenticate yourself before you can access this endpoint."

    # Test with session , should work
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar"}}
    await test_committer_auth()

    # Test with a role we don't have, should fail
    try:
        await test_member_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message == "This endpoint requires an organizational role your account does not have."

    # Test with for both member and chair, while only being member. should fail
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar", "isMember": True}}
    try:
        await test_member_and_chair_auth()
    except asfquart.auth.AuthenticationFailed as e:
        assert e.message == "This endpoint requires an organizational role your account does not have."

    # Test with for both member and chair, when we are both. should work.
    quart.session = {asfquart.APP.app_id: {"uts": time.time(), "foo": "bar", "isMember": True, "isChair": True}}
    await test_member_and_chair_auth()
