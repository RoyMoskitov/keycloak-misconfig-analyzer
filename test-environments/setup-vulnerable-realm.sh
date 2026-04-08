#!/bin/bash
KC_URL="${1:-http://localhost:8180}"
ADMIN="${2:-admin}"
PASS="${3:-adminpass}"
REALM="vulnerable-test"

# Detect python
PY=""
for cmd in /c/Users/Dima/AppData/Local/Programs/Python/Python313/python.exe python3 python; do
  if "$cmd" -c "print(1)" >/dev/null 2>&1; then PY="$cmd"; break; fi
done
if [ -z "$PY" ]; then echo "ERROR: Python not found"; exit 1; fi
echo "Using python: $PY"

echo "=== Setting up vulnerable realm '$REALM' on $KC_URL ==="

TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$ADMIN&password=$PASS" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$TOKEN" ]; then echo "ERROR: Failed to get admin token"; exit 1; fi

AUTH="Authorization: Bearer $TOKEN"
CT="Content-Type: application/json"

echo "[1/10] Creating realm..."
curl -s -X POST "$KC_URL/admin/realms" -H "$AUTH" -H "$CT" -d '{
  "realm": "'$REALM'", "enabled": true, "registrationAllowed": true, "verifyEmail": false,
  "sslRequired": "NONE", "bruteForceProtected": false, "permanentLockout": true,
  "failureFactor": 100, "waitIncrementSeconds": 5, "maxFailureWaitSeconds": 30,
  "maxDeltaTimeSeconds": 60, "minimumQuickLoginWaitSeconds": 0, "quickLoginCheckMilliSeconds": 0,
  "revokeRefreshToken": false, "refreshTokenMaxReuse": 5,
  "ssoSessionIdleTimeout": 0, "ssoSessionMaxLifespan": 0, "accessTokenLifespan": 7200,
  "accessCodeLifespan": 3600, "accessCodeLifespanLogin": 7200,
  "offlineSessionMaxLifespanEnabled": false,
  "actionTokenGeneratedByAdminLifespan": 86400, "actionTokenGeneratedByUserLifespan": 86400,
  "passwordPolicy": "length(4) and maxLength(20) and forceExpiredPasswordChange(30) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)"
}'

echo "[2/10] Weak OTP policy..."
curl -s -X PUT "$KC_URL/admin/realms/$REALM" -H "$AUTH" -H "$CT" -d '{
  "otpPolicyType": "hotp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 4,
  "otpPolicyPeriod": 60, "otpPolicyLookAheadWindow": 5
}'

echo "[3/10] Vulnerable public client..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "vulnerable-spa", "enabled": true, "publicClient": true,
  "standardFlowEnabled": true, "implicitFlowEnabled": true, "directAccessGrantsEnabled": true,
  "consentRequired": false, "fullScopeAllowed": true, "redirectUris": ["*"], "webOrigins": ["*"],
  "attributes": {"use.refresh.tokens": "true"}
}'

echo "[4/10] Vulnerable confidential client..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "vulnerable-backend", "enabled": true, "publicClient": false,
  "standardFlowEnabled": true, "implicitFlowEnabled": true, "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true, "consentRequired": false, "fullScopeAllowed": true,
  "secret": "weak-secret",
  "redirectUris": ["http://evil.example.com/*", "http://attacker.com/*"], "webOrigins": ["*"],
  "attributes": {"access.token.lifespan": "86400"}
}'

echo "[5/10] Implicit-only + disabled + logout-vulnerable clients..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{"clientId":"implicit-only-client","enabled":true,"publicClient":true,"standardFlowEnabled":false,"implicitFlowEnabled":true,"redirectUris":["https://example.com/*"]}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{"clientId":"old-unused-client","enabled":false,"publicClient":false}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{"clientId":"logout-vulnerable","enabled":true,"publicClient":false,"standardFlowEnabled":true,"frontchannelLogout":true,"consentRequired":true,"attributes":{"post.logout.redirect.uris":"http://anywhere.com"}}'

echo "[6/10] Default users..."
for U in admin test demo guest root; do
  curl -s -X POST "$KC_URL/admin/realms/$REALM/users" -H "$AUTH" -H "$CT" -d '{"username":"'$U'","enabled":true,"credentials":[{"type":"password","value":"Aa1!xxxx","temporary":true}]}'
done
curl -s -X POST "$KC_URL/admin/realms/$REALM/users" -H "$AUTH" -H "$CT" -d '{"username":"stale-user","enabled":true,"requiredActions":["UPDATE_PASSWORD"],"credentials":[{"type":"password","value":"Aa1!temp","temporary":true}]}'

echo "[7/10] Scanner user..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/users" -H "$AUTH" -H "$CT" -d '{"username":"scanner-admin","enabled":true,"credentials":[{"type":"password","value":"Sc@n1pass","temporary":false}]}'
SID=$(curl -s "$KC_URL/admin/realms/$REALM/users?username=scanner-admin" -H "$AUTH" | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
RMID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" -H "$AUTH" | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
AROLE=$(curl -s "$KC_URL/admin/realms/$REALM/clients/$RMID/roles/realm-admin" -H "$AUTH")
curl -s -X POST "$KC_URL/admin/realms/$REALM/users/$SID/role-mappings/clients/$RMID" -H "$AUTH" -H "$CT" -d "[$AROLE]"
curl -s -X PUT "$KC_URL/admin/realms/$REALM/users/$SID" -H "$AUTH" -H "$CT" -d '{"requiredActions":[]}'

echo "[8/10] Disable account-console..."
ACID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=account-console" -H "$AUTH" | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
[ -n "$ACID" ] && curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$ACID" -H "$AUTH" -H "$CT" -d '{"enabled":false}'

echo "[9/10] Identity Providers with trustEmail..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/identity-provider/instances" -H "$AUTH" -H "$CT" -d '{"alias":"evil-idp","providerId":"oidc","enabled":true,"trustEmail":true,"config":{"clientId":"fake","clientSecret":"fake","authorizationUrl":"https://evil.example.com/auth","tokenUrl":"https://evil.example.com/token","trustEmail":"true"}}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/identity-provider/instances" -H "$AUTH" -H "$CT" -d '{"alias":"another-idp","providerId":"oidc","enabled":true,"trustEmail":true,"config":{"clientId":"another","clientSecret":"another","authorizationUrl":"https://another.example.com/auth","tokenUrl":"https://another.example.com/token","trustEmail":"true"}}'

echo "[10/10] Disable required actions..."
curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/required-actions/UPDATE_PASSWORD" -H "$AUTH" -H "$CT" -d '{"alias":"UPDATE_PASSWORD","name":"Update Password","enabled":false}'
curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/required-actions/CONFIGURE_TOTP" -H "$AUTH" -H "$CT" -d '{"alias":"CONFIGURE_TOTP","name":"Configure OTP","enabled":false}'

echo ""
echo "=== Done! Scan with: ==="
echo '{"serverUrl":"'$KC_URL'","realm":"'$REALM'","clientId":"admin-cli","username":"scanner-admin","password":"Sc@n1pass"}'
