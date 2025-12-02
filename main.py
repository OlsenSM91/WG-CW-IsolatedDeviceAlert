import os
import json
import time
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

STATE_PATH = Path("/data/state.json")


def load_state() -> Dict[str, Any]:
    if STATE_PATH.exists():
        with STATE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "devices": {},          # key: f"{wgc_id}:{device_id}"
        "tenants": {},          # key: wgc_id -> {name, last_seen}
        "cw_company_cache": {}, # key: tenant_name -> cw_company_id
        "fallback_company_id": None,
        "last_tenant_sync": None,
        "last_device_poll": None,
        "audience_cache": {},   # key: wgc_id -> audience
        "tenant_token_cache": {}, # key: wgc_id -> {token, expires_at}
    }


def save_state(state: Dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with STATE_PATH.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# ------------- Env -------------#

WG_AUTH_URL = os.getenv("WG_AUTH_URL", "https://api.usa.cloud.watchguard.com/oauth/token")
WG_ACCESS_ID = os.getenv("WG_ACCESS_ID")
WG_ACCESS_PASSWORD = os.getenv("WG_ACCESS_PASSWORD")
WG_API_KEY = os.getenv("WG_API_KEY")
WG_REGION = os.getenv("WG_REGION", "usa")
WG_PARTNER_ACCOUNT_ID = os.getenv("WG_PARTNER_ACCOUNT_ID")

WG_BASE_EPDR_URL = os.getenv(
    "WG_BASE_EPDR_URL",
    f"https://api.{WG_REGION}.cloud.watchguard.com/rest/endpoint-security/management/api/v1"
)
WG_BASE_ACCOUNTS_URL = os.getenv(
    "WG_BASE_ACCOUNTS_URL",
    f"https://api.{WG_REGION}.cloud.watchguard.com/rest/platform/accounts/v1"
)

TENANT_REFRESH_MINUTES = int(os.getenv("TENANT_REFRESH_MINUTES", "1440"))  # 24 hours
DEVICE_POLL_MINUTES = int(os.getenv("DEVICE_POLL_MINUTES", "60"))          # 1 hour

# ConnectWise
CW_BASE_URL = os.getenv("CW_BASE_URL")
CW_AUTH_COMPANY = os.getenv("CW_COMPANY_ID")
CW_PUBLIC_KEY = os.getenv("CW_PUBLIC_KEY")
CW_PRIVATE_KEY = os.getenv("CW_PRIVATE_KEY")
CW_CLIENT_ID = os.getenv("CW_CLIENT_ID")

CW_DEFAULT_BOARD_ID = int(os.getenv("CW_DEFAULT_BOARD_ID", "1"))
CW_HOLLISTER_BOARD_ID = int(os.getenv("CW_HOLLISTER_BOARD_ID", "36"))
CW_DEFAULT_STATUS_ID = int(os.getenv("CW_DEFAULT_STATUS_ID", "1"))
CW_DEFAULT_PRIORITY_ID = int(os.getenv("CW_DEFAULT_PRIORITY_ID", "3"))
CW_DEFAULT_SOURCE_ID = int(os.getenv("CW_DEFAULT_SOURCE_ID", "7"))

CW_FALLBACK_COMPANY_NAME = os.getenv("CW_FALLBACK_COMPANY_NAME", "COMPUTER NETWORKING SOLUTIONS INC.")


# ------------- WatchGuard helpers -------------#

def get_wg_access_token() -> str:
    """Get partner (ACC account) token."""
    if not all([WG_ACCESS_ID, WG_ACCESS_PASSWORD, WG_API_KEY, WG_PARTNER_ACCOUNT_ID]):
        raise RuntimeError("Missing WatchGuard env vars (WG_ACCESS_ID, WG_ACCESS_PASSWORD, WG_API_KEY, WG_PARTNER_ACCOUNT_ID).")

    pair = f"{WG_ACCESS_ID}:{WG_ACCESS_PASSWORD}"
    auth_bytes = pair.encode("utf-8")
    auth_header = base64.b64encode(auth_bytes).decode("ascii")

    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "api-access",
    }

    resp = requests.post(WG_AUTH_URL, headers=headers, data=data, timeout=30)
    resp.raise_for_status()
    token_data = resp.json()
    token = token_data.get("access_token")
    if not token:
        raise RuntimeError("No access_token in WatchGuard auth response")
    return token


def get_audience_for_tenant(partner_token: str, wgc_id: str, state: Dict[str, Any]) -> str:
    """Get audience for a WGC tenant, cached in state."""
    audience_cache = state.setdefault("audience_cache", {})

    if wgc_id in audience_cache:
        return audience_cache[wgc_id]

    # Request audience from API
    url = f"https://api.{WG_REGION}.cloud.watchguard.com/rest/platform/authorization/v1/audiences"
    headers = {
        "Authorization": f"Bearer {partner_token}",
        "WatchGuard-API-Key": WG_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {"accountId": wgc_id}

    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    audience = data.get("audience")

    if not audience:
        raise RuntimeError(f"No audience returned for {wgc_id}")

    # Cache it
    audience_cache[wgc_id] = audience
    print(f"[INFO] Cached audience for {wgc_id}: {audience}")
    return audience


def get_tenant_token(wgc_id: str, audience: str, state: Dict[str, Any]) -> str:
    """Get tenant-scoped token for WGC, with caching."""
    token_cache = state.setdefault("tenant_token_cache", {})

    # Check if we have a valid cached token
    if wgc_id in token_cache:
        cached = token_cache[wgc_id]
        expires_at = parse_iso(cached.get("expires_at"))
        if expires_at and datetime.utcnow() < expires_at - timedelta(minutes=5):
            # Token still valid (with 5 min buffer)
            return cached["token"]

    # Request new tenant token
    pair = f"{WG_ACCESS_ID}:{WG_ACCESS_PASSWORD}"
    auth_bytes = pair.encode("utf-8")
    auth_header = base64.b64encode(auth_bytes).decode("ascii")

    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "api-access",
        "audience": audience,
    }

    resp = requests.post(WG_AUTH_URL, headers=headers, data=data, timeout=30)
    resp.raise_for_status()
    token_data = resp.json()
    token = token_data.get("access_token")
    expires_in = token_data.get("expires_in", 3600)  # Default 1 hour

    if not token:
        raise RuntimeError(f"No access_token for tenant {wgc_id}")

    # Cache with expiration
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    token_cache[wgc_id] = {
        "token": token,
        "expires_at": expires_at.isoformat(),
    }

    return token


def fetch_managed_tenants(token: str, acc_id: str) -> List[Dict[str, Any]]:
    url = (
        f"{WG_BASE_ACCOUNTS_URL}/accounts/{acc_id}/children"
        "?type=2&includeDelegatedAccounts=true&limit=-1"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "WatchGuard-API-Key": WG_API_KEY,
        "Accept": "application/json",
    }
    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    items = data.get("items", [])
    tenants = []
    for item in items:
        account_id = item.get("accountId", "")
        if account_id.startswith("WGC-"):
            tenants.append(
                {
                    "wgc_id": account_id,
                    "name": item.get("name", ""),
                    "type": item.get("type"),
                }
            )
    return tenants


def fetch_devices_for_tenant(tenant_token: str, wgc_id: str) -> List[Dict[str, Any]]:
    """Fetch devices for a tenant using tenant-scoped token."""
    url = (
        f"{WG_BASE_EPDR_URL}/accounts/{wgc_id}/devices"
        "?$count=true&$orderby=hostname&$config=true"
    )
    headers = {
        "Authorization": f"Bearer {tenant_token}",
        "WatchGuard-API-Key": WG_API_KEY,
        "Accept": "application/json",
    }
    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", [])


# ------------- ConnectWise helpers -------------#

def cw_auth_headers() -> Dict[str, str]:
    if not all([CW_BASE_URL, CW_AUTH_COMPANY, CW_PUBLIC_KEY, CW_PRIVATE_KEY, CW_CLIENT_ID]):
        raise RuntimeError("Missing ConnectWise env vars.")
    auth_string = f"{CW_AUTH_COMPANY}+{CW_PUBLIC_KEY}:{CW_PRIVATE_KEY}"
    auth_bytes = auth_string.encode("utf-8")
    auth_header = base64.b64encode(auth_bytes).decode("ascii")

    return {
        "Authorization": f"Basic {auth_header}",
        "clientId": CW_CLIENT_ID,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def cw_search_company_by_name_exact(name: str) -> Optional[int]:
    headers = cw_auth_headers()
    # Exact match conditions: name="Some Name"
    # URL encode the quotes
    cond = f'name="{name}"'
    params = {"conditions": cond}
    url = f"{CW_BASE_URL}/company/companies"
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if resp.status_code not in (200, 201):
        print(f"[WARN] CW exact company search failed for {name}: {resp.status_code}")
        return None
    companies = resp.json()
    if len(companies) == 1:
        return companies[0].get("id")
    # 0 or multiple results - not confident enough
    return None


def cw_search_company_by_name_like(name: str) -> Optional[int]:
    headers = cw_auth_headers()
    # Basic "like" search: name like "%partial%"
    # This can return multiple; if so we will not guess.
    cond = f'name like "%{name}%"'
    params = {"conditions": cond}
    url = f"{CW_BASE_URL}/company/companies"
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if resp.status_code not in (200, 201):
        print(f"[WARN] CW like company search failed for {name}: {resp.status_code}")
        return None
    companies = resp.json()
    if len(companies) == 1:
        return companies[0].get("id")
    return None


def get_or_cache_fallback_company_id(state: Dict[str, Any]) -> int:
    if state.get("fallback_company_id"):
        return state["fallback_company_id"]

    headers = cw_auth_headers()
    cond = f'name="{CW_FALLBACK_COMPANY_NAME}"'
    params = {"conditions": cond}
    url = f"{CW_BASE_URL}/company/companies"
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    resp.raise_for_status()
    companies = resp.json()
    if not companies:
        raise RuntimeError(f"Fallback company '{CW_FALLBACK_COMPANY_NAME}' not found in ConnectWise.")
    cid = companies[0].get("id")
    state["fallback_company_id"] = cid
    print(f"[INFO] Fallback CW company id for '{CW_FALLBACK_COMPANY_NAME}' is {cid}")
    return cid


def resolve_cw_company_for_tenant(tenant_name: str, state: Dict[str, Any]) -> int:
    cache = state.setdefault("cw_company_cache", {})
    if tenant_name in cache:
        return cache[tenant_name]

    # Try exact name first
    cid = cw_search_company_by_name_exact(tenant_name)
    if cid:
        print(f"[INFO] Mapped WG tenant '{tenant_name}' to CW company id {cid} (exact match).")
        cache[tenant_name] = cid
        return cid

    # Try like search
    cid = cw_search_company_by_name_like(tenant_name)
    if cid:
        print(f"[INFO] Mapped WG tenant '{tenant_name}' to CW company id {cid} (like match).")
        cache[tenant_name] = cid
        return cid

    # Fallback
    fallback_id = get_or_cache_fallback_company_id(state)
    print(f"[WARN] Could not confidently map WG tenant '{tenant_name}', using fallback company id {fallback_id}.")
    cache[tenant_name] = fallback_id
    return fallback_id


def determine_board_id(tenant_name: str) -> int:
    """Determine which CW board to use based on tenant/client name."""
    # Check if "Hollister" is in the tenant name
    if "hollister" in tenant_name.lower():
        print(f"[INFO] Using Hollister board (ID {CW_HOLLISTER_BOARD_ID}) for tenant '{tenant_name}'")
        return CW_HOLLISTER_BOARD_ID

    # Default to San Jose board
    print(f"[INFO] Using San Jose board (ID {CW_DEFAULT_BOARD_ID}) for tenant '{tenant_name}'")
    return CW_DEFAULT_BOARD_ID


def create_cw_ticket_for_isolation(
    device: Dict[str, Any],
    tenant_wgc_id: str,
    tenant_name: str,
    cw_company_id: int,
) -> int:
    headers = cw_auth_headers()

    host = device.get("host_name")
    ip = device.get("ip_address")
    os_name = device.get("operating_system")
    last_conn = device.get("last_connection")
    isolation_state = device.get("isolation_state")
    domain = device.get("domain")
    site_name = device.get("site_name")

    # Determine which board to use based on tenant name
    board_id = determine_board_id(tenant_name)

    summary = f"WatchGuard EPDR isolated endpoint {host}"

    description_lines = [
        "WatchGuard EPDR reports this endpoint is isolated.",
        "",
        f"WG Account ID: {tenant_wgc_id}",
        f"WG Tenant: {tenant_name}",
        f"WG Site: {site_name}",
        f"Host: {host}",
        f"IP: {ip}",
        f"Domain: {domain}",
        f"OS: {os_name}",
        f"Isolation state: {isolation_state}",
        f"Last connection: {last_conn}",
    ]
    description = "\n".join(description_lines)

    payload: Dict[str, Any] = {
        "summary": summary,
        "initialDescription": description,
        "board": {"id": board_id},
        "status": {"id": CW_DEFAULT_STATUS_ID},
        "priority": {"id": CW_DEFAULT_PRIORITY_ID},
        "source": {"id": CW_DEFAULT_SOURCE_ID},
        "company": {"id": cw_company_id},
    }

    url = f"{CW_BASE_URL}/service/tickets"
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    if resp.status_code not in (200, 201):
        try:
            print("[ERROR] CW ticket create failed:", resp.status_code, resp.json())
        except Exception:
            print("[ERROR] CW ticket create failed:", resp.status_code, resp.text)
        resp.raise_for_status()
    ticket = resp.json()
    ticket_id = ticket.get("id")
    print(f"[INFO] Created CW ticket {ticket_id} for host {host} in tenant {tenant_name}")
    return ticket_id


def add_note_to_ticket(ticket_id: int, note_text: str) -> None:
    headers = cw_auth_headers()
    url = f"{CW_BASE_URL}/service/tickets/{ticket_id}/notes"
    payload = {
        "text": note_text,
        "detailDescriptionFlag": True,
        "internalAnalysisFlag": False,
        "resolutionFlag": False,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    if resp.status_code not in (200, 201):
        try:
            print(f"[WARN] Failed to add note to ticket {ticket_id}:", resp.status_code, resp.json())
        except Exception:
            print(f"[WARN] Failed to add note to ticket {ticket_id}:", resp.status_code, resp.text)


# ------------- Core logic -------------#

def parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def should_run_tenant_sync(state: Dict[str, Any]) -> bool:
    last = parse_iso(state.get("last_tenant_sync"))
    if not last:
        return True
    return datetime.utcnow() - last >= timedelta(minutes=TENANT_REFRESH_MINUTES)


def should_run_device_poll(state: Dict[str, Any]) -> bool:
    # Monday is 0, Sunday is 6
    weekday = datetime.utcnow().weekday()
    if weekday > 4:
        # Sat or Sun - skip
        return False
    last = parse_iso(state.get("last_device_poll"))
    if not last:
        return True
    return datetime.utcnow() - last >= timedelta(minutes=DEVICE_POLL_MINUTES)


def run_tenant_sync(state: Dict[str, Any], token: str) -> None:
    print("[INFO] Running tenant sync from WatchGuard ACC account...")
    tenants = fetch_managed_tenants(token, WG_PARTNER_ACCOUNT_ID)
    tmap = state.setdefault("tenants", {})
    now = datetime.utcnow().isoformat()

    # Add the ACC account itself (parent) to be monitored
    tmap[WG_PARTNER_ACCOUNT_ID] = {
        "name": "COMPUTER NETWORKING SOLUTIONS INC.",
        "last_seen": now,
    }
    print(f"[INFO] Added ACC account {WG_PARTNER_ACCOUNT_ID} to monitoring")

    # Add all child WGC tenants
    for t in tenants:
        wgc_id = t["wgc_id"]
        tmap[wgc_id] = {
            "name": t["name"],
            "last_seen": now,
        }
    state["last_tenant_sync"] = now
    print(f"[INFO] Tenant sync complete, found {len(tenants)} child tenants + 1 ACC account = {len(tenants) + 1} total.")


def run_device_poll(state: Dict[str, Any], partner_token: str) -> None:
    """Poll devices for all tenants using tenant-scoped tokens."""
    tenants = state.get("tenants", {})
    if not tenants:
        print("[WARN] No tenants in state, skipping device poll.")
        return

    devices_state = state.setdefault("devices", {})
    now = datetime.utcnow().isoformat()

    for wgc_id, tinfo in tenants.items():
        tenant_name = tinfo.get("name", wgc_id)

        try:
            # ACC accounts use partner token directly, WGC accounts need tenant tokens
            if wgc_id.startswith("ACC-"):
                # Use partner token directly for ACC account
                tenant_token = partner_token
                print(f"[INFO] Using partner token for ACC account {wgc_id}")
            else:
                # Get audience for this WGC tenant (cached)
                audience = get_audience_for_tenant(partner_token, wgc_id, state)

                # Get tenant-scoped token (cached with expiration)
                tenant_token = get_tenant_token(wgc_id, audience, state)

            # Fetch devices using appropriate token
            devices = fetch_devices_for_tenant(tenant_token, wgc_id)
            print(f"[INFO] Fetched {len(devices)} devices for tenant {tenant_name} ({wgc_id})")

        except Exception as e:
            print(f"[ERROR] Failed to fetch devices for tenant {tenant_name} ({wgc_id}): {e}")
            continue

        cw_company_id = resolve_cw_company_for_tenant(tenant_name, state)

        for device in devices:
            device_id = device.get("device_id")
            if not device_id:
                continue
            key = f"{wgc_id}:{device_id}"
            iso_state = int(device.get("isolation_state", 0))

            old = devices_state.get(key, {})
            old_iso_state = int(old.get("isolation_state", 0))
            existing_ticket_id = old.get("ticket_id")

            # New isolation 0 -> nonzero
            if old_iso_state == 0 and iso_state != 0:
                try:
                    ticket_id = create_cw_ticket_for_isolation(
                        device=device,
                        tenant_wgc_id=wgc_id,
                        tenant_name=tenant_name,
                        cw_company_id=cw_company_id,
                    )
                    devices_state[key] = {
                        "isolation_state": iso_state,
                        "ticket_id": ticket_id,
                    }
                except Exception as e:
                    print(f"[ERROR] Failed to create ticket for {key}: {e}")
                    # still record new iso state so we do not spam retries blindly
                    devices_state[key] = {
                        "isolation_state": iso_state,
                        "ticket_id": existing_ticket_id,
                    }

            # Isolation cleared nonzero -> 0
            elif old_iso_state != 0 and iso_state == 0:
                devices_state[key] = {
                    "isolation_state": iso_state,
                    "ticket_id": existing_ticket_id,
                }
                if existing_ticket_id:
                    try:
                        add_note_to_ticket(existing_ticket_id, "Endpoint is no longer isolated in WatchGuard EPDR.")
                    except Exception as e:
                        print(f"[WARN] Failed to add note for {key}: {e}")

            else:
                # No state transition, just update iso and keep ticket id
                devices_state[key] = {
                    "isolation_state": iso_state,
                    "ticket_id": existing_ticket_id,
                }

    state["last_device_poll"] = now
    print("[INFO] Device poll cycle complete.")


def main_loop():
    state = load_state()
    print("[INFO] WatchGuard EPDR isolation watcher starting up.")

    while True:
        try:
            token = get_wg_access_token()
        except Exception as e:
            print("[ERROR] Failed to get WatchGuard token:", e)
            time.sleep(60)
            continue

        changed = False

        if should_run_tenant_sync(state):
            try:
                run_tenant_sync(state, token)
                changed = True
            except Exception as e:
                print("[ERROR] Tenant sync failed:", e)

        if should_run_device_poll(state):
            try:
                run_device_poll(state, token)
                changed = True
            except Exception as e:
                print("[ERROR] Device poll failed:", e)

        if changed:
            save_state(state)

        # Sleep 5 minutes between loops.
        # The should_run_ functions handle the actual cadence.
        time.sleep(300)


if __name__ == "__main__":
    main_loop()