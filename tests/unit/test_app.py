"""Unit tests for the Greeter Lambda. Run: python -m pytest tests/unit"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
os.environ["APP_VERSION"] = "v-test"
os.environ["ENV_NAME"] = "unit"
import app  # noqa: E402


def call(path, name=None, method="GET"):
    event = {"rawPath": path, "requestContext": {"http": {"method": method}}}
    if name is not None:
        event["queryStringParameters"] = {"name": name}
    r = app.handler(event, None)
    return r["statusCode"], json.loads(r["body"])


def test_health_reports_version_and_env():
    assert call("/health") == (200, {"status": "ok", "version": "v-test", "env": "unit"})


def test_greet():
    assert call("/greet", "Sam") == (200, {"message": "Hello, Sam!", "version": "v-test"})


def test_greet_trims_spaces():
    assert call("/greet", "   Ann  ")[1]["message"] == "Hello, Ann!"


def test_empty_name_is_rejected():
    for name in (None, "", "    "):
        status, body = call("/greet", name)
        assert status == 400 and body["error"] == "Please enter your name."


def test_name_length_limit():
    assert call("/greet", "x" * 50)[0] == 200
    status, body = call("/greet", "x" * 51)
    assert status == 400 and "50 characters" in body["error"]


def test_unknown_route_and_method():
    assert call("/nope")[0] == 404
    assert call("/greet", "Sam", method="POST")[0] == 404
