"""Shared pytest fixtures.

Sets dummy AWS credentials so moto's mocked backends accept requests and no
real AWS call is ever made.
"""

import os

import boto3
import pytest


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    """Dummy credentials + region for every test (moto never calls AWS)."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def region():
    return "us-east-1"


@pytest.fixture
def session():
    return boto3.Session(region_name="us-east-1")
