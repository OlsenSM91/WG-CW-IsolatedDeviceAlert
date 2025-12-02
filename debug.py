import os
import base64
import sys
from typing import Dict, Any, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"


def banner():
    print(CYAN + r"""
  /$$$$$$  /$$   /$$  /$$$$$$  /$$   /$$ /$$   /$$
 /$$__  $$| $$$ | $$ /$$__  $$| $$  | $$| $$  | $$
| $$  \__/| $$$$| $$| $$  \__/| $$  | $$| $$  | $$
| $$      | $$ $$ $$|  $$$$$$ | $$$$$$$$| $$  | $$
| $$      | $$  $$$$ \____  $$|_____  $$| $$  | $$
| $$    $$| $$\  $$$ /$$  \ $$      | $$| $$  | $$
|  $$$$$$/| $$ \  $$|  $$$$$$/      | $$|  $$$$$$/
 \______/ |__/  \__/ \______/       |__/ \______/ 
                                                  
            WatchGuard EPDR → ConnectWise
                Environment Debug Tool
""" + RESET)


def header(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def ok(msg: str):
    print(f"{GREEN}[OK]{RESET}   {msg}")


def fail(msg: str):
    print(f"{RED}[FAIL]{RESET} {msg}")


def info(msg: str):
    print(f"{YELLOW}[INFO]{RESET} {msg}")


def warn(msg: str):
    print(f"{YELLOW}[WARN]{RESET} {msg}")


def check_env() -> bool:
    header("1. Checking required environment variables")

    required = [
        "WG_ACCESS_ID",
        "WG_ACCESS_PASSWORD",
        "WG_API_KEY",
        "WG_PARTNER_ACCOUNT_ID",
        "WG_AUTH_URL",
        "WG_REGION",
        "CW_BASE_URL",
        "CW_COMPANY_ID",
        "CW_PUBLIC_KEY",
        "CW_PRIVATE_KEY",
        "CW_CLIENT_ID",
        "CW_DEFAULT_BOARD_ID",
        "CW_DEFAULT_STATUS_ID",
        "CW_DEFAULT_PRIORITY_ID",
        "CW_DEFAULT_SOURCE_ID",
        "CW_FALLBACK_COMPANY_NAME",
    ]

    ok_all = True
    for key in required:
        val = os.getenv(key)
        if not val:
            fail(f"{key} is not set")
            ok_all = False
        else:
            ok(f"{key} is set")

    if ok_all:
        ok("All required env vars are present")
    else:
        warn("Some required env vars are missing. Fix these before running the watcher.")

    return ok_all


# ------------- WatchGuard helpers -------------

def get_partner_token() -> Optional[str]:
    header("2. Testing WatchGuard partner token (ACC level)")

    access_id = os.getenv("WG_ACCESS_ID")
    password = os.getenv("WG_ACCESS_PASSWORD")
    auth_url = os.getenv("WG_AUTH_URL", "https://api.usa.cloud.watchguard.com/oauth/token")

    if not access_id or not password:
        fail("WG_ACCESS_ID or WG_ACCESS_PASSWORD missing, cannot test")
        return None

    pair = f"{access_id}:{password}"
    auth_bytes = pair.encode("utf-8")
    auth_header = base64.b64encode(auth_bytes).decode("ascii")

    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "api-access",
    }

    try:
        resp = requests.post(auth_url, headers=headers, data=data, timeout=30)
        info(f"Token response status: {resp.status_code}")
        resp.raise_for_status()
        token_data = resp.json()
        token = token_data.get("access_token")
        if token:
            ok("WatchGuard partner token retrieved successfully")
            return token
        else:
            fail("No access_token field in WatchGuard response")
            print(token_data)
            return None
    except Exception as e:
        fail(f"Error requesting partner token: {e}")
        return None


def test_tenant_discovery(partner_token: str) -> List[Dict[str, Any]]:
    header("3. Testing WatchGuard tenant discovery (Accounts API)")

    api_key = os.getenv("WG_API_KEY")
    region = os.getenv("WG_REGION", "usa")
    acc_id = os.getenv("WG_PARTNER_ACCOUNT_ID")

    if not acc_id:
        fail("WG_PARTNER_ACCOUNT_ID is not set")
        return []

    base_accounts_url = os.getenv(
        "WG_BASE_ACCOUNTS_URL",
        f"https://api.{region}.cloud.watchguard.com/rest/platform/accounts/v1",
    )

    url = f"{base_accounts_url}/accounts/{acc_id}/children"
    params = {
        "type": 2,
        "includeDelegatedAccounts": "true",
        "limit": -1,
    }
    headers = {
        "Authorization": f"Bearer {partner_token}",
        "WatchGuard-API-Key": api_key,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        info(f"Tenant discovery status: {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", [])
        tenants = [
            {"wgc_id": item.get("accountId"), "name": item.get("name")}
            for item in items
            if item.get("accountId", "").startswith("WGC-")
        ]
        ok(f"Found {len(tenants)} WGC tenants")
        for t in tenants[:10]:
            print(f"      - {t['wgc_id']}  {t['name']}")
        if len(tenants) > 10:
            print(f"      ... and {len(tenants) - 10} more")
        return tenants
    except Exception as e:
        fail(f"Error during tenant discovery: {e}")
        return []


def get_audience_for_tenant(partner_token: str, wgc_id: str) -> Optional[str]:
    api_key = os.getenv("WG_API_KEY")
    region = os.getenv("WG_REGION", "usa")

    url = f"https://api.{region}.cloud.watchguard.com/rest/platform/authorization/v1/audiences"
    headers = {
        "Authorization": f"Bearer {partner_token}",
        "WatchGuard-API-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {"accountId": wgc_id}

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        info(f"Audience request for {wgc_id} status: {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        audience = data.get("audience")
        if audience:
            ok(f"Got audience for tenant {wgc_id}")
            return audience
        else:
            fail(f"No audience returned for tenant {wgc_id}")
            print(data)
            return None
    except Exception as e:
        fail(f"Error requesting audience for {wgc_id}: {e}")
        return None


def get_tenant_token(audience: str) -> Optional[str]:
    access_id = os.getenv("WG_ACCESS_ID")
    password = os.getenv("WG_ACCESS_PASSWORD")
    auth_url = os.getenv("WG_AUTH_URL", "https://api.usa.cloud.watchguard.com/oauth/token")

    pair = f"{access_id}:{password}"
    auth_bytes = pair.encode("utf-8")
    auth_header = base64.b64encode(auth_bytes).decode("ascii")

    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "api-access",
        "audience": audience,
    }

    try:
        resp = requests.post(auth_url, headers=headers, data=data, timeout=30)
        info(f"Tenant token status: {resp.status_code}")
        resp.raise_for_status()
        token_data = resp.json()
        token = token_data.get("access_token")
        if token:
            ok("Tenant scoped token retrieved")
            return token
        else:
            fail("No access_token field in tenant token response")
            print(token_data)
            return None
    except Exception as e:
        fail(f"Error requesting tenant token: {e}")
        return None


def test_epdr_devices(tenant_token: str, wgc_id: str):
    header("4. Testing EPDR devices API for one tenant")

    api_key = os.getenv("WG_API_KEY")
    region = os.getenv("WG_REGION", "usa")

    base_epdr_url = os.getenv(
        "WG_BASE_EPDR_URL",
        f"https://api.{region}.cloud.watchguard.com/rest/endpoint-security/management/api/v1",
    )

    url = f"{base_epdr_url}/accounts/{wgc_id}/devices"
    params = {
        "$count": "true",
        "$orderby": "hostname",
        "$config": "true",
    }
    headers = {
        "Authorization": f"Bearer {tenant_token}",
        "WatchGuard-API-Key": api_key,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        info(f"Devices API status for {wgc_id}: {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        devices = data.get("data", [])
        ok(f"Retrieved {len(devices)} devices from EPDR")
        for d in devices[:5]:
            print(f"      - {d.get('host_name')}  iso={d.get('isolation_state')}  ip={d.get('ip_address')}")
        if len(devices) == 0:
            warn("No devices returned. EPDR may not be deployed yet for this tenant.")
    except Exception as e:
        fail(f"Error fetching devices for {wgc_id}: {e}")


# ------------- ConnectWise helpers -------------

def cw_auth_headers() -> Dict[str, str]:
    base_url = os.getenv("CW_BASE_URL")
    company = os.getenv("CW_COMPANY_ID")
    pub = os.getenv("CW_PUBLIC_KEY")
    priv = os.getenv("CW_PRIVATE_KEY")
    client_id = os.getenv("CW_CLIENT_ID")

    if not all([base_url, company, pub, priv, client_id]):
        raise RuntimeError("Missing one or more CW env vars")

    auth_string = f"{company}+{pub}:{priv}"
    auth_bytes = auth_string.encode("utf-8")
    auth_header = base64.b64encode(auth_bytes).decode("ascii")

    return {
        "Authorization": f"Basic {auth_header}",
        "clientId": client_id,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def test_cw_auth() -> bool:
    header("5. Testing ConnectWise authentication")

    base_url = os.getenv("CW_BASE_URL")
    headers = cw_auth_headers()
    url = f"{base_url}/system/info"

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        info(f"CW /system/info status: {resp.status_code}")
        resp.raise_for_status()
        info_json = resp.json()
        ok("ConnectWise auth successful")
        print(f"      Site: {info_json.get('companyName')}  Version: {info_json.get('version')}")
        return True
    except Exception as e:
        fail(f"ConnectWise auth test failed: {e}")
        return False


def test_cw_boards() -> bool:
    header("6. Testing ConnectWise boards list")

    base_url = os.getenv("CW_BASE_URL")
    headers = cw_auth_headers()
    url = f"{base_url}/service/boards"

    try:
        resp = requests.get(url, headers=headers, timeout=60)
        info(f"CW boards status: {resp.status_code}")
        resp.raise_for_status()
        boards = resp.json()
        ok(f"Retrieved {len(boards)} boards")
        for b in boards[:10]:
            print(f"      - id={b.get('id')}  name={b.get('name')}")
        return True
    except Exception as e:
        fail(f"Board list failed: {e}")
        return False


def test_cw_statuses() -> bool:
    """
    Advisory check only.

    Uses board-scoped statuses endpoint. Many CW roles cannot hit global /service/statuses,
    so this tries /service/boards/{boardId}/statuses instead.

    If this fails with 403 or similar, we WARN but do NOT treat it as a hard failure,
    since you can still manually validate status IDs in the CW UI.
    """
    header("7. Testing ConnectWise statuses list (board-scoped, advisory)")

    base_url = os.getenv("CW_BASE_URL")
    headers = cw_auth_headers()
    board_id = os.getenv("CW_DEFAULT_BOARD_ID")

    if not board_id:
        warn("CW_DEFAULT_BOARD_ID not set; skipping status check")
        return False

    url = f"{base_url}/service/boards/{board_id}/statuses"

    try:
        resp = requests.get(url, headers=headers, timeout=60)
        info(f"CW statuses status: {resp.status_code}")

        if resp.status_code == 403:
            warn("403 Forbidden for board statuses. Your CW security role may not allow REST status queries. "
                 "You can still verify CW_DEFAULT_STATUS_ID in the CW UI.")
            return False

        resp.raise_for_status()
        statuses = resp.json()
        ok(f"Retrieved {len(statuses)} statuses for board {board_id}")
        for s in statuses[:10]:
            print(f"      - id={s.get('id')}  name={s.get('name')}")
        return True
    except Exception as e:
        warn(f"Status list check failed (advisory only): {e}")
        return False


def test_cw_fallback_company() -> bool:
    header("8. Testing ConnectWise fallback company mapping")

    base_url = os.getenv("CW_BASE_URL")
    fallback_name = os.getenv("CW_FALLBACK_COMPANY_NAME", "")
    if not fallback_name:
        fail("CW_FALLBACK_COMPANY_NAME not set")
        return False

    headers = cw_auth_headers()
    cond = f'name="{fallback_name}"'
    params = {"conditions": cond}
    url = f"{base_url}/company/companies"

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        info(f"CW company search status: {resp.status_code}")
        resp.raise_for_status()
        companies = resp.json()
        if not companies:
            fail(f"No company found for fallback name '{fallback_name}'")
            return False
        elif len(companies) > 1:
            warn(f"Multiple companies found for fallback name '{fallback_name}'")
            for c in companies:
                print(f"      - id={c.get('id')} name={c.get('name')}")
            return True
        else:
            cid = companies[0].get("id")
            ok(f"Fallback company found: id={cid}, name={fallback_name}")
            return True
    except Exception as e:
        fail(f"Fallback company lookup failed: {e}")
        return False


def main():
    banner()
    any_fail = False

    if not check_env():
        any_fail = True

    partner_token = get_partner_token()
    if not partner_token:
        any_fail = True
    else:
        tenants = test_tenant_discovery(partner_token)
        if tenants:
            sample = tenants[0]
            wgc_id = sample["wgc_id"]
            print(f"\n{YELLOW}[INFO]{RESET} Using sample tenant {wgc_id} ({sample['name']}) for EPDR tests")
            audience = get_audience_for_tenant(partner_token, wgc_id)
            if audience:
                tenant_token = get_tenant_token(audience)
                if tenant_token:
                    test_epdr_devices(tenant_token, wgc_id)
                else:
                    any_fail = True
            else:
                any_fail = True
        else:
            any_fail = True

    if not test_cw_auth():
        any_fail = True

    if not test_cw_boards():
        any_fail = True

    # Status test is advisory only, do not flip any_fail based on it
    _ = test_cw_statuses()

    if not test_cw_fallback_company():
        any_fail = True

    print("\n" + "=" * 80)
    if any_fail:
        fail("One or more required checks failed. Fix the reported issues before running the watcher.")
        sys.exit(1)
    else:
        ok("All required checks completed successfully. Advisory checks (like statuses) may still show WARN, which is fine.")
        sys.exit(0)


if __name__ == "__main__":
    main()