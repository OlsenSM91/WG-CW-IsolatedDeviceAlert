# Troubleshooting

This section covers the most common issues when deploying the WatchGuard EPDR watcher and how to validate both WatchGuard and ConnectWise independently.

---

## 0. Debug Script

There is a python script called `debug.py`. This script covers pretty much all of the below steps in once process.

<img width="737" height="709" alt="Screenshot 2025-12-02 103743" src="https://github.com/user-attachments/assets/2a359c10-93aa-40ee-bd16-3d32a0e13ea1" />

This script can also be used to get board IDs and other needed information for ticket creation so long as you have your CW API variables and WG API variables set in the `.env` file.

The `debug.py` will perform the following checks:
1. Checking required environment variables
2. Testing WatchGuard partner token (ACC level)
3. Testing WatchGuard tenant discovery (Accounts API)
4. Testing EPDR devices API for one tenant
5. Testing ConnectWise authentication
6. Testing ConnectWise boards list
7. Testing ConnectWise statuses list (board-scoped, advisory)
8. Testing ConnectWise fallback company mapping

# Manually checking and other Troubleshooting

## 1. Container starts but does nothing

### Symptoms

* No output in `docker logs`
* No `state.json` file created
* Exits immediately or silently loops

### Checks

#### Confirm container is running:
```bash
docker ps
```

#### View logs:
```bash
docker logs -f wg-epdr-cw-watcher
```

If you see **nothing**, check:

* Is `.env` mounted?
* Did Compose start successfully?
* Any `Exited (1)` state?

```bash
docker ps -a
```

---

## 2. WatchGuard authentication fails (401 / token errors)

### Symptoms

* `Failed to get WatchGuard token`
* HTTP 401/403 from WatchGuard APIs
* No tenant or device data being fetched

---

### Validate WatchGuard token generation

Run this PowerShell test locally:
```powershell
$AccessId = "WG_ACCESS_ID"
$Password = "WG_ACCESS_PASSWORD"

$bytes = [System.Text.Encoding]::ASCII.GetBytes("$AccessId`:$Password")
$base64 = [Convert]::ToBase64String($bytes)

$response = Invoke-RestMethod `
  -Method POST `
  -Uri "https://api.usa.cloud.watchguard.com/oauth/token" `
  -Headers @{
      Authorization="Basic $base64"
      "Content-Type"="application/x-www-form-urlencoded"
  } `
  -Body "grant_type=client_credentials&scope=api-access"

$response.access_token
```

If this fails:

* Wrong password
* Wrong Access ID
* OAuth not enabled for this identity in WatchGuard Cloud

---

### Validate tenant discovery (Accounts API)

Replace with your real ACC ID:
```powershell
$token = "PASTE_ACCESS_TOKEN"
$ApiKey = "WG_API_KEY"
$AccId  = "ACC-xxxxxxx"

Invoke-RestMethod `
  -Method GET `
  -Uri "https://api.usa.cloud.watchguard.com/rest/platform/accounts/v1/accounts/$AccId/children?type=2&includeDelegatedAccounts=true&limit=-1" `
  -Headers @{
      Authorization="Bearer $token"
      "WatchGuard-API-Key"=$ApiKey
  }
```

If this fails:

* Access identity does not have partner permissions
* API Key is not valid
* ACC ID is wrong

---

### Validate tenant audience + tenant token flow

For one client `WGC-xxxxx`:

#### Step 1: Request audience
```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri "https://api.usa.cloud.watchguard.com/rest/platform/authorization/v1/audiences" `
  -Headers @{
      Authorization="Bearer $token"
      "WatchGuard-API-Key"=$ApiKey
      "Content-Type"="application/json"
  } `
  -Body (@{accountId="WGC-xxxxxxxx"} | ConvertTo-Json)
```

Response should include:
```json
{
  "audience": "xxxxxxxxxxx"
}
```

If this fails:

* Your account does not have delegation access
* Invalid WGC ID

---

#### Step 2: Request tenant-scoped token
```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri "https://api.usa.cloud.watchguard.com/oauth/token" `
  -Headers @{
      Authorization="Basic $base64"
      "Content-Type"="application/x-www-form-urlencoded"
  } `
  -Body "grant_type=client_credentials&scope=api-access&audience=PASTE_AUDIENCE"
```

If this fails:

* Audience invalid
* Wrong Access ID/password
* EPDR permission not assigned to identity

---

#### Step 3: Fetch device list using tenant token
```powershell
$TenantToken="PASTE_TENANT_TOKEN"

Invoke-RestMethod `
  -Method GET `
  -Uri "https://api.usa.cloud.watchguard.com/rest/endpoint-security/management/api/v1/accounts/WGC-xxxxxxxx/devices" `
  -Headers @{
      Authorization="Bearer $TenantToken"
      "WatchGuard-API-Key"=$ApiKey
  }
```

If this fails:

* Token is expired
* Wrong audience
* Invalid tenant

---

## 3. Client mapping to ConnectWise fails

### Symptoms

* Log shows:

  ```
  Could not confidently map tenant, using fallback company
  ```
* Tickets always go to CNS

---

### Validate company exists:
```bash
GET /company/companies?conditions=name="CLIENT NAME"
```

PowerShell test:
```powershell
Invoke-RestMethod `
  -Method GET `
  -Uri "$CW_BASE_URL/company/companies?conditions=name=`"Client Name`"" `
  -Headers @{
      Authorization="Basic BASE64_COMPANY+KEY"
      clientId="CW_CLIENT_ID"
  }
```

---

### Validate fallback exists

Make sure:
```
COMPUTER NETWORKING SOLUTIONS INC.
```

exists verbatim in CW.

If not, edit `.env`:

```env
CW_FALLBACK_COMPANY_NAME=Your Exact CW Company Name
```

---

## 4. Tickets fail to create

### Symptoms

* `CW ticket create failed`
* Status 400 / 403 / 404
* Nothing appears in Manage

---

### Validate board IDs

This project uses:

* Default board: `CW_DEFAULT_BOARD_ID`
* Hollister board (if name contains `Hollister`): `CW_HOLLISTER_BOARD_ID`

Test:
```powershell
Invoke-RestMethod `
  -Method GET `
  -Uri "$CW_BASE_URL/service/boards" `
  -Headers @{
      Authorization="Basic BASE64_COMPANY+KEY"
      clientId="CW_CLIENT_ID"
  }
```

Verify board IDs match env values.

---

### Validate status values
```powershell
Invoke-RestMethod `
  -Method GET `
  -Uri "$CW_BASE_URL/service/statuses" `
  -Headers @{
      Authorization="Basic BASE64_COMPANY+KEY"
      clientId="CW_CLIENT_ID"
  }
```

Confirm:

* `CW_DEFAULT_STATUS_ID`
* `CW_DEFAULT_PRIORITY_ID`
* `CW_DEFAULT_SOURCE_ID`

---

## 5. No tickets ever appear

### Checklist

Confirm all are true:

| Check                  | Required |
| ---------------------- | -------- |
| Tenant sync works      | Yes      |
| Devices returned       | Yes      |
| isolation_state != 0   | Yes      |
| Company resolved       | Yes      |
| Board ID valid         | Yes      |
| Status ID valid        | Yes      |
| ConnectWise auth works | Yes      |

Also inspect `/data/state.json`:

```bash
cat data/state.json
```

Look for:

* `tenants`
* `devices`
* `cw_company_cache`
* `fallback_company_id`
* `audience_cache`
* `tenant_token_cache`

If `devices` shows entries but no tickets:

* Mapping or ticket creation is failing
* Check CW logs above

---

## 6. Service stuck or behaving strangely

### Reset state (safe)

If mapping or caching gets weird:
```bash
rm -f data/state.json
docker restart wg-epdr-cw-watcher
```

It will re-build:

* Tenants
* Audiences
* Tokens
* CW mapping

---

## 7. Logging tips

Follow logs live:
```bash
docker logs -f wg-epdr-cw-watcher
```

With timestamps:
```bash
docker logs -f --timestamps wg-epdr-cw-watcher
```

Last N lines:
```bash
docker logs --tail=200 wg-epdr-cw-watcher
```
