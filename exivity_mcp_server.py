"""
Exivity MCP Server (FastMCP)
----------------------------
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union, Tuple, List

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

# ----------------------
# FOCUS Schema Constants
# ----------------------

# Standard FOCUS 1.0 Columns (subset of commonly used ones + core identifiers)
FOCUS_COLUMNS = [
    "BillingPeriodStart",
    "BillingPeriodEnd",
    "BillingAccountName",
    "BillingAccountId",
    "BilledCost",
    "BillingCurrency",
    "ProviderName",
    "RegionName",
    "AvailabilityZone",
    "ServiceName",
    "ResourceName",
    "ResourceId",
    "UsageType",
    "UsageUnit",
    "UsageQuantity",
    "ListCost",
    "EffectiveCost",
    "PricingUnit",
    "SkuId",
    "ChargeType",
    "ChargeDescription",
]

# Default best-effort mapping from common Exivity/Cloud fields to FOCUS
DEFAULT_FOCUS_MAPPING = {
    # Cost
    "total_charge": "BilledCost",
    "subtotal_charge": "ListCost",  # Approximation
    "total_cogs": "ContractedCost",  # Approximation
    "unit_based_subtotal_charge": "ListCost",
    # Identifiers
    "account_id": "BillingAccountId",
    "account_name": "BillingAccountName",
    "account_key": "SubAccountId",  # Often used as sub-identifier
    # Resource / Service
    "service_description": "ServiceName",
    "service_key": "SkuId",
    "servicecategory_name": "ServiceCategory",
    "service_id": "ResourceId",
    # Quantities
    "total_quantity": "UsageQuantity",
    "subtotal_quantity": "PricingQuantity",
    # Rates
    "avg_unit_based_rate": "ListUnitPrice",
    # Dates
    "start_date": "BillingPeriodStart",
    "end_date": "BillingPeriodEnd",
    # Fallbacks / Legacy
    "cost": "BilledCost",
    "usage": "UsageQuantity",
    "date": "BillingPeriodStart",
    "account": "BillingAccountName",
    "service": "ServiceName",
    "resource": "ResourceName",
    "region": "RegionName",
    "zone": "AvailabilityZone",
    "provider": "ProviderName",
    "currency": "BillingCurrency",
}


def _redact(val: Optional[str]) -> str:
    if not val:
        return ""
    if len(val) <= 3:
        return REDACTED
    return f"{val[:1]}…{val[-1:]}"


def _parse_ssl_verify() -> Union[bool, str]:
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
    """Thin wrapper around httpx for the Exivity API."""

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
        params: Optional[Union[Dict[str, Any], List[Tuple[str, Any]]]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.cfg.base_url}{path}"

        # Determine best-effort Accept from params.format
        accept = "*/*"
        fmt = None
        try:
            if isinstance(params, dict):
                fmt = params.get("format")
            elif isinstance(params, list):
                for k, v in params:
                    if k == "format":
                        fmt = v
                        break
        except Exception:
            pass
        if isinstance(fmt, bytes):
            fmt = fmt.decode("utf-8", "ignore")
        if isinstance(fmt, str):
            f = fmt.lower()
            if f.startswith("csv"):
                accept = "text/csv, */*;q=0.8"
            elif f.startswith("pdf"):
                accept = "application/pdf, */*;q=0.8"
            else:
                accept = "application/json, */*;q=0.8"

        hdrs = {"Accept": accept}
        if headers:
            hdrs.update(headers)

        auth = None
        if self.cfg.token:
            hdrs["Authorization"] = f"Bearer {self.cfg.token}"
        elif self.cfg.username and self.cfg.password:
            auth = httpx.BasicAuth(self.cfg.username, self.cfg.password)

        # ---------- Debug: request line ----------
        try:
            from httpx import QueryParams

            qp_str = f"?{QueryParams(params)}" if params else ""
        except Exception:
            qp_str = f" params={params!r}" if params else ""
        auth_mode = (
            "Bearer"
            if self.cfg.token
            else ("Basic" if (self.cfg.username and self.cfg.password) else "None")
        )
        tls_desc = (
            self.cfg.ssl_verify
            if isinstance(self.cfg.ssl_verify, str)
            else ("verify=True" if self.cfg.ssl_verify else "verify=False")
        )
        print(
            f"[Exivity MCP][request] {method.upper()} {url}{qp_str}  tls={tls_desc}  auth={auth_mode}"
        )

        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                resp = self._client.request(
                    method.upper(),
                    url,
                    params=params,
                    json=json_body,
                    data=data,
                    headers=hdrs,
                    auth=auth,
                )
                print(
                    f"[Exivity MCP][request] <- status={resp.status_code} content-type={resp.headers.get('content-type', '')!r}"
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
            except (
                httpx.ReadTimeout,
                httpx.ConnectTimeout,
                httpx.RemoteProtocolError,
            ) as e:
                last_exc = e
                print(
                    f"[Exivity MCP][request] transient error on attempt {attempt + 1}: {e}"
                )
                time.sleep(0.5 * (attempt + 1))
            except httpx.RequestError as e:
                print(f"[Exivity MCP][request] HTTP request error: {e}")
                raise RuntimeError(f"HTTP request error: {e}") from e
        raise RuntimeError(f"HTTP request failed after retries: {last_exc}")


# ----------------------
# FastMCP Server & Tools
# ----------------------

mcp = FastMCP(name="Exivity MCP")
_client = ExivityClient(ExivityConfig())


# Shared GET implementation so tools don't call each other
def _get_impl(
    path: str, params: Optional[Union[Dict[str, Any], List[Tuple[str, Any]]]] = None
) -> Dict[str, Any]:
    return _client.request("GET", path, params=params)


# Expose an ASGI app for optional HTTP hosting
try:
    app = mcp.streamable_http_app()
except Exception:
    app = None


@mcp.tool
def ping() -> str:
    return "pong"


@mcp.tool
def config() -> dict:
    ca_bundle = (
        _client.cfg.ssl_verify if isinstance(_client.cfg.ssl_verify, str) else None
    )
    return {
        "base_url": _client.cfg.base_url,
        "basic_auth": bool(_client.cfg.username and _client.cfg.password),
        "username_preview": _redact(_client.cfg.username),
        "tls": {
            "verify": _client.cfg.ssl_verify
            if isinstance(_client.cfg.ssl_verify, bool)
            else True,
            "ca_bundle": ca_bundle,
        },
        "auth_mode": "Bearer"
        if _client.cfg.token
        else ("Basic" if (_client.cfg.username and _client.cfg.password) else "None"),
    }


@mcp.tool
def set_base_url(base_url: str) -> dict:
    _client.set_base_url(base_url)
    return {"ok": True, "base_url": _client.cfg.base_url}


@mcp.tool
def set_basic_auth(username: str, password: str) -> dict:
    _client.set_basic_auth(username, password)
    return {"ok": True, "username_preview": _redact(_client.cfg.username)}


@mcp.tool
def clear_auth() -> dict:
    _client.clear_auth()
    return {"ok": True}


@mcp.tool
def set_ssl_verify(enable: bool) -> dict:
    _client.set_ssl_verify(enable)
    return {"ok": True, "verify": bool(enable)}


@mcp.tool
def set_ca_bundle(ca_bundle_path: str) -> dict:
    _client.set_ca_bundle(ca_bundle_path)
    return {"ok": True, "ca_bundle": ca_bundle_path}


@mcp.tool
def set_token(token: Optional[str] = None) -> dict:
    _client.set_token(token)
    return {"ok": True, "auth_mode": "Bearer" if token else "None"}


@mcp.tool
def get_token(username: str, password: str) -> dict:
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": username, "password": password}
    result = _client.request("POST", "/v1/auth/token", headers=headers, data=data)
    tok = None
    if isinstance(result, dict):
        tok = result.get("token") or result.get("access_token")
    if tok:
        print("DEBUG: Auto-saving token from auth response")
        _client.set_token(tok)
    return result


@mcp.tool
def get(
    path: str, params: Optional[Union[Dict[str, Any], List[Tuple[str, Any]]]] = None
) -> Dict[str, Any]:
    return _get_impl(path, params=params)


@mcp.tool
def post(path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    result = _client.request("POST", path, json_body=body or {})
    if isinstance(result, dict) and ("token" in result or "access_token" in result):
        print("DEBUG: Auto-saving token from POST response")
        _client.set_token(result.get("token") or result.get("access_token"))
    return result


@mcp.tool
def put(path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _client.request("PUT", path, json_body=body or {})


@mcp.tool
def delete(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _client.request("DELETE", path, params=params)


# --- helpers for run_report ---
def _normalize_yyyy_mm_dd(s: Optional[str]) -> Optional[str]:
    """Allow YYYYMMDD and convert to YYYY-MM-DD."""
    if not s:
        return s
    if len(s) == 8 and s.isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}"
    return s


def _run_report_impl(
    report_id: int,
    start: Optional[str] = None,
    end: Optional[str] = None,
    dimension: Optional[str] = None,
    timeline: Optional[str] = None,
    depth: Optional[int] = None,
    include: Optional[Union[str, List[str]]] = None,
    filters: Optional[Dict[str, Any]] = None,
    format: str = "json",
    precision: Optional[str] = None,
    progress: Optional[int] = None,
    csv_delimiter: Optional[str] = None,
    csv_decimal_separator: Optional[str] = None,
    summary_options: Optional[str] = None,
    extra_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Helper implementing the logic for GET /v1/reports/{report_id}/run."""

    def add(k: str, v: Any, out: List[Tuple[str, str]]) -> None:
        if v is None:
            return
        if isinstance(v, (list, tuple, set)):
            for item in v:
                out.append((k, str(item)))
        else:
            out.append((k, str(v)))

    # Preserve originals for fallback
    orig_start, orig_end = start, end

    def build_params(use_normalized: bool) -> List[Tuple[str, str]]:
        p: List[Tuple[str, str]] = []
        s = _normalize_yyyy_mm_dd(orig_start) if use_normalized else orig_start
        e = _normalize_yyyy_mm_dd(orig_end) if use_normalized else orig_end

        add("start", s, p)
        add("end", e, p)
        add("dimension", dimension, p)
        add("timeline", timeline, p)
        add("depth", depth, p)

        if include is not None:
            include_str = (
                include if isinstance(include, str) else ",".join(map(str, include))
            )
            add("include", include_str, p)

        add("format", format, p)
        add("precision", precision, p)
        if progress is not None:
            add("progress", progress, p)
        add("csv_delimiter", csv_delimiter, p)
        add("csv_decimal_separator", csv_decimal_separator, p)
        add("summary_options", summary_options, p)

        # filters -> filter[key] or filter[key][op]
        if filters:
            f = dict(filters)
            if "parent_account_id" in f and "account_id" not in f:
                f["account_id"] = f.pop("parent_account_id")
            for key, val in f.items():
                if isinstance(val, dict):
                    for op, v in val.items():
                        add(f"filter[{key}][{op}]", v, p)
                else:
                    add(f"filter[{key}]", val, p)

        if extra_params:
            for k, v in extra_params.items():
                add(k, v, p)

        return p

    path = f"/v1/reports/{report_id}/run"

    def debug_print(params: List[Tuple[str, str]], label: str) -> None:
        try:
            from httpx import QueryParams

            qp = QueryParams(params)
            qp_str = str(qp)
        except Exception:
            qp_str = repr(params)
        print(
            "\n[Exivity MCP][run_report] -------------------------------------------------"
        )
        print(f"[run_report] base_url          : {_client.cfg.base_url}")
        auth_mode = (
            "Bearer"
            if _client.cfg.token
            else (
                "Basic" if (_client.cfg.username and _client.cfg.password) else "None"
            )
        )
        print(f"[run_report] auth_mode         : {auth_mode}")
        print(f"[run_report] username_preview  : {_redact(_client.cfg.username)}")
        if isinstance(_client.cfg.ssl_verify, bool):
            print(f"[run_report] TLS verify        : {_client.cfg.ssl_verify}")
        else:
            print(f"[run_report] TLS CA bundle     : {_client.cfg.ssl_verify}")
        print(f"[run_report] path              : {path}")
        print(f"[run_report] attempt           : {label}")
        print(f"[run_report] params (raw list) : {params}")
        print(f"[run_report] encoded query     : {qp_str}")
        print(f"[run_report] preview URL       : {_client.cfg.base_url}{path}?{qp_str}")

    last_exc: Optional[Exception] = None
    # Try raw dates first (YYYYMMDD if provided), then normalized (YYYY-MM-DD)
    for use_normalized, label in ((False, "raw-dates"), (True, "normalized-dates")):
        params = build_params(use_normalized)
        debug_print(params, label)
        try:
            resp = _get_impl(path, params=params)
            print(f"[run_report] response type     : {type(resp).__name__}")
            if isinstance(resp, dict):
                keys = list(resp.keys())
                print(f"[run_report] response keys     : {keys[:10]}")
                if "error" in resp:
                    print(
                        f"[run_report] response.error    : {str(resp['error'])[:300]}"
                    )
            else:
                print(f"[run_report] response preview  : {str(resp)[:300]}")
            print(
                "[Exivity MCP][run_report] ------------------------------- END -------------\n"
            )
            return resp
        except Exception as e:
            last_exc = e
            print(f"[run_report] attempt {label} failed: {e}")
            print(
                "[Exivity MCP][run_report] ------------------------------- RETRY ----------"
            )

    print("[run_report] EXCEPTION (both attempts failed)")
    print(
        "[Exivity MCP][run_report] ------------------------------- END (ERROR) -----\n"
    )
    raise last_exc if last_exc else RuntimeError("run_report failed without exception")


@mcp.tool
def run_report(
    report_id: int,
    start: Optional[str] = None,
    end: Optional[str] = None,
    dimension: Optional[str] = None,
    timeline: Optional[str] = None,
    depth: Optional[int] = None,
    include: Optional[Union[str, List[str]]] = None,
    filters: Optional[Dict[str, Any]] = None,
    format: str = "json",
    precision: Optional[str] = None,
    progress: Optional[int] = None,
    csv_delimiter: Optional[str] = None,
    csv_decimal_separator: Optional[str] = None,
    summary_options: Optional[str] = None,
    extra_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    GET /v1/reports/{report_id}/run with robust param handling + debug.

    Change: Do NOT force date normalization. Try raw dates first (e.g., YYYYMMDD),
    then retry once with normalized YYYY-MM-DD if the first attempt fails.
    """
    return _run_report_impl(
        report_id=report_id,
        start=start,
        end=end,
        dimension=dimension,
        timeline=timeline,
        depth=depth,
        include=include,
        filters=filters,
        format=format,
        precision=precision,
        progress=progress,
        csv_delimiter=csv_delimiter,
        csv_decimal_separator=csv_decimal_separator,
        summary_options=summary_options,
        extra_params=extra_params,
    )


@mcp.tool
def run_focus_report(
    report_id: int,
    start: Optional[str] = None,
    end: Optional[str] = None,
    dimension: Optional[str] = None,
    timeline: Optional[str] = None,
    depth: Optional[int] = None,
    include: Optional[Union[str, List[str]]] = None,
    filters: Optional[Dict[str, Any]] = None,
    precision: Optional[str] = None,
    extra_params: Optional[Dict[str, Any]] = None,
    custom_mapping: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Runs an Exivity report and transforms the result to the FinOps FOCUS schema (1.0).

    Args:
        report_id: ID of the report to run.
        start: Start date (YYYYMMDD or YYYY-MM-DD).
        end: End date (YYYYMMDD or YYYY-MM-DD).
        dimension: Group by dimension.
        timeline: Timeline granularity (day, month).
        depth: Depth of the report.
        include: Fields to include.
        filters: Filters to apply.
        precision: Precision of the output.
        extra_params: Additional parameters.
        custom_mapping: Optional dictionary to override default column mappings.
                        Format: {'exivity_column': 'FOCUS_Column'}
    """
    # 1. Fetch raw data
    # Force JSON format for parsing
    # 1. Fetch raw data
    # Force JSON format for parsing
    # Automatically add dimensions and includes for richer data if not specified
    if not dimension:
        dimension = "accounts,services,instances"

    if not include:
        include = [
            "account_key",
            "account_name",
            "service_key",
            "service_description",
            "servicecategory_name",
            "start_date",
            "end_date",
        ]

    raw_data = _run_report_impl(
        report_id=report_id,
        start=start,
        end=end,
        dimension=dimension,
        timeline=timeline,
        depth=depth,
        include=include,
        filters=filters,
        format="json",  # Always JSON for transformation
        precision=precision,
        extra_params=extra_params,
    )

    # 2. Extract records
    records = []
    if isinstance(raw_data, list):
        records = raw_data
    elif isinstance(raw_data, dict):
        # Handle common wrapper keys if present
        if "data" in raw_data and isinstance(raw_data["data"], list):
            records = raw_data["data"]
        elif "result" in raw_data and isinstance(raw_data["result"], list):
            records = raw_data["result"]
        elif "rows" in raw_data and isinstance(raw_data["rows"], list):
            records = raw_data["rows"]
        else:
            # Check if it's a dict of lists (case where keys are IDs)
            found_lists = [v for v in raw_data.values() if isinstance(v, list)]
            if found_lists:
                for lst in found_lists:
                    records.extend(lst)
            else:
                # Fallback: maybe the dict itself is the record?
                records = [raw_data]

    if not records:
        return {"result": [], "metadata": {"status": "empty or unknown format"}}

    # 3. Transform records
    mapping = DEFAULT_FOCUS_MAPPING.copy()
    if custom_mapping:
        mapping.update(custom_mapping)

    transformed_records = []
    for row in records:
        if not isinstance(row, dict):
            continue

        new_row = {}
        # Apply mapping
        for exivity_key, val in row.items():
            focus_key = mapping.get(exivity_key)
            if focus_key:
                new_row[focus_key] = val
            else:
                # Keep original key if no mapping found (optional: or drop it?)
                # FOCUS spec says we can have provider-specific cols, usually prefixed.
                # We'll keep them as is for now or map to 'x_Exivity_<key>'?
                # Better to keep them for context.
                new_row[exivity_key] = val

        # Ensure minimal set of FOCUS columns exist (nullable)
        for col in FOCUS_COLUMNS:
            if col not in new_row:
                new_row[col] = None

        transformed_records.append(new_row)

    return {
        "focus_version": "1.0",
        "record_count": len(transformed_records),
        "data": transformed_records,
    }


if __name__ == "__main__":
    if os.getenv("SELF_TEST"):
        print("[self-test] config ->")
        print(json.dumps(config(), indent=2))
    else:
        mcp.run()
