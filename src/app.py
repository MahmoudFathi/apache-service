"""Greeter API - one Lambda behind an API Gateway HTTP API (payload format 2.0).

    GET /health          -> {"status": "ok", "version": "v7", "env": "test"}
    GET /greet?name=Sam  -> {"message": "Hello, Sam!", "version": "v7"}
"""

import json
import os

VERSION = os.environ.get("APP_VERSION", "dev")
ENV_NAME = os.environ.get("ENV_NAME", "local")
MAX_NAME = 50


def reply(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def health():
    return reply(200, {"status": "ok", "version": VERSION, "env": ENV_NAME})


def greet(event):
    name = ((event.get("queryStringParameters") or {}).get("name") or "").strip()
    if not name:
        return reply(400, {"error": "Please enter your name."})
    if len(name) > MAX_NAME:
        return reply(400, {"error": f"Name must be {MAX_NAME} characters or fewer."})
    return reply(200, {"message": f"Hello, {name}!", "version": VERSION})


def handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    path = event.get("rawPath", "")
    if method == "GET" and path == "/health":
        return health()
    if method == "GET" and path == "/greet":
        return greet(event)
    return reply(404, {"error": "Not found"})
