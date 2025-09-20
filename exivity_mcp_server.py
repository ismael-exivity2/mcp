"""
Exivity MCP Server (FastMCP) — No JWT + SSL toggle
--------------------------------------------------
A small, extensible MCP server that exposes tools for interacting with the
Exivity REST API **without JWTs** (uses HTTP Basic Auth per request) and with a
runtime **SSL verification toggle** (for lab/self-signed scenarios).

Requires:
    pip install fastmcp httpx python-dotenv
    # Optional (for HTTP hosting): pip install uvicorn

Environment variables (preferred for secrets):
    EXIVITY_BASE_URL      # e.g. https://api.exivity.com or your instance URL
    EXIVITY_USERNAME      # basic auth username
    EXIVITY_PASSWORD      # basic auth password
    EXIVITY_SSL_VERIFY    # true/false (default: true). Set to false to DISABLE TLS verification.
    EXIVITY_CA_BUNDLE     # path to custom CA bundle (overrides EXIVITY_SSL_VERIFY)

Run (stdio MCP):
    python exivity_mcp_server.py

HTTP (optional) — if you want an ASGI app to serve via uvicorn:
    uvicorn exivity_mcp_server:app --host 0.0.0.0 --port 8000

Security note:
- Disabling TLS verification exposes you to MITM attacks. Prefer using
  EXIVITY_CA_BUNDLE to trust your internal/self-signed CA instead of disabling.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

import httpx
from fastmcp import FastMCP

# ----------------------
# Config / Utilities
# ----------------------

DEFAULT_BASE_URL = os.getenv("EXIVITY_BASE_URL", "https://api.exivity.com").rstrip("/")
DEFAULT_USERNAME = os.getenv("EXIVITY_USERNAME")
DEFAULT_PASSWORD = os.getenv("EXIVITY_PASSWORD")
DEFAULT_CA_BUNDLE = os.getenv("EXIVITY_CA_BUNDLE")

REDACTED = "***REDACTED***"


def _redact(val: Optional[str]) -> str:
    if not val:
        return ""
    if len(val) <= 3:
        return REDACTED
    return f"{val[:1]}…{val[-1:]}"  # tiny preview only


def _parse_ssl_verify() -> Union[bool, str]:
    """Return bool or CA bundle path for httpx verify=…"""
    if DEFAULT_CA_BUNDLE:
        return DEFAULT_CA_BUNDLE
    env = (os.getenv("EXIVITY_SSL_VERIFY", "true") or "true").strip().lower()
    if env in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    return True


@dataclass
class ExivityConfig:
    base_url: str = DEFAULT_BASE_URL
    username: Optional[str] = DEFAULT_USERNAME
    password: Optional[str] = DEFAULT_PASSWORD
    ssl_verify: Union[bool, str] = _parse_ssl_verify()
    token: Optional[str] = None


class ExivityClient:
    """Thin wrapper around httpx for the Exivity API (Basic Auth) with SSL toggle."""

    def __init__(self, cfg: ExivityConfig):
        self.cfg = cfg
        self._client = self._make_client()

    def _make_client(self) -> httpx.Client:
        return httpx.Client(timeout=30.0, verify=self.cfg.ssl_verify)

    def _rebuild_client(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
        self._client = self._make_client()

    # --- auth/helpers ---
    def set_basic_auth(self, username: str, password: str) -> None:
        self.cfg.username = username
        self.cfg.password = password

    def clear_auth(self) -> None:
        self.cfg.username = None
        self.cfg.password = None

    def set_base_url(self, base_url: str) -> None:
        self.cfg.base_url = base_url.rstrip("/")

    def set_ssl_verify(self, enable: bool) -> None:
        self.cfg.ssl_verify = bool(enable)
        self._rebuild_client()

    def set_ca_bundle(self, ca_bundle_path: str) -> None:
        self.cfg.ssl_verify = ca_bundle_path
        self._rebuild_client()

    def set_token(self, token: Optional[str]) -> None:
        self.cfg.token = token

    # --- core request ---
    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.cfg.base_url}{path}"

        hdrs = {"Accept": "application/json"}
        if headers:
            hdrs.update(headers)

        auth = None
        if self.cfg.token:
            hdrs["Authorization"] = f"Bearer {self.cfg.token}"
        elif self.cfg.username and self.cfg.password:
            auth = httpx.BasicAuth(self.cfg.username, self.cfg.password)


        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                resp = self._client.request(
                    method.upper(), url, params=params, json=json_body, data=data, headers=hdrs, auth=auth
                )
                if resp.status_code >= 400:
                    try:
                        err = resp.json()
                    except Exception:
                        err = {"error": resp.text[:500]}
                    raise RuntimeError(
                        json.dumps(
                            {
                                "message": "Exivity API returned error",
                                "status": resp.status_code,
                                "url": url,
                                "method": method.upper(),
                                "error": err,
                            },
                            ensure_ascii=False,
                        )
                    )
                ctype = resp.headers.get("content-type", "")
                if "application/json" in ctype:
                    return resp.json()
                try:
                    return resp.json()
                except Exception:
                    return {"text": resp.text}
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError) as e:
                last_exc = e
                time.sleep(0.5 * (attempt + 1))
            except httpx.RequestError as e:
                raise RuntimeError(f"HTTP request error: {e}") from e
        raise RuntimeError(f"HTTP request failed after retries: {last_exc}")


# ----------------------
# FastMCP Server & Tools
# ----------------------

mcp = FastMCP(name="Exivity MCP")
_client = ExivityClient(ExivityConfig())

# Expose an ASGI app for optional HTTP hosting
try:
    app = mcp.streamable_http_app()
except Exception:
    app = None


@mcp.tool
def ping() -> str:
    """Simple health check for the MCP server itself."""
    return "pong"


@mcp.tool
def config() -> dict:
    """Return current base URL, auth status, and TLS settings (redacted where needed)."""
    ca_bundle = _client.cfg.ssl_verify if isinstance(_client.cfg.ssl_verify, str) else None
    return {
        "base_url": _client.cfg.base_url,
        "basic_auth": bool(_client.cfg.username and _client.cfg.password),
        "username_preview": _redact(_client.cfg.username),
        "tls": {
            "verify": _client.cfg.ssl_verify if isinstance(_client.cfg.ssl_verify, bool) else True,
            "ca_bundle": ca_bundle,
        },
    }


@mcp.tool
def set_base_url(base_url: str) -> dict:
    """Set the Exivity API base URL. Example: https://api.exivity.com"""
    _client.set_base_url(base_url)
    return {"ok": True, "base_url": _client.cfg.base_url}


@mcp.tool
def set_basic_auth(username: str, password: str) -> dict:
    """Configure HTTP Basic Auth (username + password)."""
    _client.set_basic_auth(username, password)
    return {"ok": True, "username_preview": _redact(_client.cfg.username)}


@mcp.tool
def clear_auth() -> dict:
    """Clear any configured credentials from memory."""
    _client.clear_auth()
    return {"ok": True}


@mcp.tool
def set_ssl_verify(enable: bool) -> dict:
    """Enable or disable TLS certificate verification for outbound Exivity calls.

    SECURITY: Disabling verification is unsafe. Prefer set_ca_bundle() with a
    trusted CA file instead of globally disabling verification.
    """
    _client.set_ssl_verify(enable)
    return {"ok": True, "verify": bool(enable)}


@mcp.tool
def set_ca_bundle(ca_bundle_path: str) -> dict:
    """Set a custom CA bundle file path for TLS verification (safer than disabling)."""
    _client.set_ca_bundle(ca_bundle_path)
    return {"ok": True, "ca_bundle": ca_bundle_path}

@mcp.tool
def set_token(token: Optional[str] = None) -> dict:
    """Set JWT token for subsequent requests."""
    _client.set_token(token)
    return {"ok": True}


@mcp.tool
def get_token(username: str, password: str) -> dict:
    """Get a JWT token from the Exivity API using username and password."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "username": username,
        "password": password
    }
    result = _client.request("POST", "/v1/auth/token", headers=headers, data=data)
    if isinstance(result, dict) and "token" in result:
        _client.set_token(result["token"])
    return result


@mcp.tool
def get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Perform a GET request to the Exivity API.

    Args:
        path: API path such as "/v1/reports" or "v1/accounts" (leading slash optional)
        params: Optional query parameters
    """
    return _client.request("GET", path, params=params)


@mcp.tool
def post(path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Perform a POST request to the Exivity API with a JSON body."""
    result = _client.request("POST", path, json_body=body or {})
    # Auto-save token from auth responses
    if isinstance(result, dict) and "token" in result:
        print(f"DEBUG: Auto-saving token from response")
        _client.set_token(result["token"])
    return result


@mcp.tool
def put(path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Perform a PUT request to the Exivity API with a JSON body."""
    return _client.request("PUT", path, json_body=body or {})


@mcp.tool
def delete(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Perform a DELETE request to the Exivity API."""
    return _client.request("DELETE", path, params=params)


@mcp.tool
@mcp.tool
def run_report(
    report_id: int,
    start: Optional[str] = None,
    end: Optional[str] = None,
    dimension: Optional[str] = None,
    timeline: Optional[str] = None,
    depth: Optional[int] = None,
    include: Optional[Union[str, list]] = None,
    filters: Optional[Dict[str, Any]] = None,
    format: str = "json",
    precision: Optional[str] = None,
    progress: Optional[int] = 1,
    csv_delimiter: Optional[str] = None,
    csv_decimal_separator: Optional[str] = None,
    summary_options: Optional[str] = None,
    extra_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Thin wrapper that calls `get()` for GET /v1/reports/{report_id}/run."""
    def add(k: str, v: Any, out: list):
        if v is None:
            return
        if isinstance(v, (list, tuple, set)):
            for item in v:
                out.append((k, str(item)))
        else:
            out.append((k, str(v)))

    params: list[tuple[str, str]] = []
    add("start", start, params)
    add("end", end, params)
    add("dimension", dimension, params)
    add("timeline", timeline, params)
    add("depth", depth, params)

    # include: accept list or string; API expects comma-separated string
    if include is not None:
        include_str = include if isinstance(include, str) else ",".join(map(str, include))
        add("include", include_str, params)

    add("format", format, params)
    add("precision", precision, params)
    if progress is not None:
        add("progress", progress, params)
    add("csv_delimiter", csv_delimiter, params)
    add("csv_decimal_separator", csv_decimal_separator, params)
    add("summary_options", summary_options, params)

    # filters → filter[foo]=bar (repeat key for list values). Also support nested ops.
    if filters:
        # optional convenience: map deprecated parent_account_id → account_id
        if "parent_account_id" in filters and "account_id" not in filters:
            filters = dict(filters)
            filters["account_id"] = filters.pop("parent_account_id")
        for key, val in filters.items():
            if isinstance(val, dict):
                for op, v in val.items():
                    add(f"filter[{key}][{op}]", v, params)
            else:
                add(f"filter[{key}]", val, params)

    # passthrough any raw/advanced params exactly as provided
    if extra_params:
        for k, v in extra_params.items():
            add(k, v, params)

    path = f"/v1/reports/{report_id}/run"
    # IMPORTANT: we pass the tuple list straight through so repeats are preserved
    return get(path, params=params)


if __name__ == "__main__":
    if os.getenv("SELF_TEST"):
        print("[self-test] config ->")
        print(json.dumps(config(), indent=2))
    else:
        mcp.run()
