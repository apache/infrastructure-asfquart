#!/usr/bin/env python3
"""Tests for the package-level app"""

import asfquart


def test_app_or_none_without_an_app(monkeypatch):
    monkeypatch.setattr(asfquart, "APP", None)
    assert asfquart.app_or_none() is None


def test_app_or_none_is_the_constructed_app(tmp_path, monkeypatch):
    monkeypatch.setattr(asfquart, "APP", None)
    app = asfquart.construct("foobar", app_dir=str(tmp_path), token_file=None)
    assert asfquart.app_or_none() is app
