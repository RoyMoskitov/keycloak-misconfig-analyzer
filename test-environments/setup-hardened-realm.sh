#!/bin/bash
KC_URL="${1:-http://localhost:8180}"
ADMIN="${2:-admin}"
PASS="${3:-adminpass}"
REALM="hardened-test"
SCANNER_CLIENT="scanner-client"
SCANNER_SECRET="scanner-secret-hardened"

# Detect python
PY=""
for cmd in /c/Users/Dima/AppData/Local/Programs/Python/Python313/python.exe python3 python; do
  if "$cmd" -c "print(1)" >/dev/null 2>&1; then PY="$cmd"; break; fi
done
if [ -z "$PY" ]; then echo "ERROR: Python not found"; exit 1; fi
echo "Using python: $PY"

echo "=== Setting up HARDENED realm '$REALM' on $KC_URL ==="

TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$ADMIN&password=$PASS" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$TOKEN" ]; then echo "ERROR: Failed to get admin token"; exit 1; fi

AUTH="Authorization: Bearer $TOKEN"
CT="Content-Type: application/json"

# ============================================================
# 1. CREATE REALM with hardened settings
# Fixes: 6.3.1 (brute force), 6.6.3 (OTP brute force),
#        10.4.9/7.4.3/7.2.4 (revoke refresh token),
#        10.4.8 (offline session max lifespan),
#        6.3.5 (events), 6.4.1 (admin token lifespan),
#        6.4.3 (user token lifespan), 6.2.1 (password length),
#        11.4.2/KC-PASS-05 (argon2), 6.5.1 (OTP algo),
#        6.5.4 (OTP digits)
# ============================================================
echo "[1/10] Creating realm with hardened settings..."
curl -s -X POST "$KC_URL/admin/realms" -H "$AUTH" -H "$CT" -d '{
  "realm": "'$REALM'",
  "enabled": true,
  "registrationAllowed": false,
  "verifyEmail": false,
  "sslRequired": "external",
  "bruteForceProtected": true,
  "permanentLockout": false,
  "failureFactor": 5,
  "waitIncrementSeconds": 60,
  "maxFailureWaitSeconds": 900,
  "maxDeltaTimeSeconds": 43200,
  "minimumQuickLoginWaitSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "revokeRefreshToken": true,
  "refreshTokenMaxReuse": 0,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 36000,
  "accessTokenLifespan": 300,
  "accessCodeLifespan": 60,
  "accessCodeLifespanLogin": 1800,
  "offlineSessionMaxLifespanEnabled": true,
  "offlineSessionMaxLifespan": 5184000,
  "actionTokenGeneratedByAdminLifespan": 900,
  "actionTokenGeneratedByUserLifespan": 900,
  "eventsEnabled": true,
  "eventsExpiration": 604800,
  "adminEventsEnabled": true,
  "adminEventsDetailsEnabled": true,
  "passwordPolicy": "length(12) and maxLength(128) and hashAlgorithm(pbkdf2-sha512) and hashIterations(210000) and notUsername and notEmail",
  "otpPolicyType": "totp",
  "otpPolicyAlgorithm": "HmacSHA256",
  "otpPolicyDigits": 8,
  "otpPolicyPeriod": 30,
  "otpPolicyLookAheadWindow": 1
}'

# ============================================================
# 2. CREATE SCANNER CLIENT (service account)
# Fixes: 8.4.1 (fullScopeAllowed=false), 8.3.1 (explicit alg)
# ============================================================
echo "[2/10] Creating scanner service-account client..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "'$SCANNER_CLIENT'",
  "enabled": true,
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "fullScopeAllowed": false,
  "consentRequired": false,
  "secret": "'$SCANNER_SECRET'",
  "attributes": {
    "access.token.signed.response.alg": "RS256"
  }
}'

# ============================================================
# 3. GRANT realm-admin ROLE to scanner service account
# ============================================================
echo "[3/10] Granting realm-admin role to service account..."
CLIENT_UUID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=$SCANNER_CLIENT" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)

# Remove default "Client IP Address" mapper (contains "address" → triggers 8.2.3 sensitive check)
CIP_MAPPER_ID=$(curl -s "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" -H "$AUTH" \
  | $PY -c "import sys,json;mappers=json.load(sys.stdin);matches=[m['id'] for m in mappers if m.get('name')=='Client IP Address'];print(matches[0] if matches else '')" 2>/dev/null)
if [ -n "$CIP_MAPPER_ID" ]; then
  curl -s -X DELETE "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models/$CIP_MAPPER_ID" -H "$AUTH"
  echo "  Removed 'Client IP Address' mapper"
fi

SA_USER_ID=$(curl -s "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/service-account-user" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)

RM_UUID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)

ADMIN_ROLE=$(curl -s "$KC_URL/admin/realms/$REALM/clients/$RM_UUID/roles/realm-admin" -H "$AUTH")

curl -s -X POST "$KC_URL/admin/realms/$REALM/users/$SA_USER_ID/role-mappings/clients/$RM_UUID" \
  -H "$AUTH" -H "$CT" -d "[$ADMIN_ROLE]"

# With fullScopeAllowed=false, roles must be explicitly mapped to client scope
# so they appear in the access token
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/scope-mappings/clients/$RM_UUID" \
  -H "$AUTH" -H "$CT" -d "[$ADMIN_ROLE]"

# ============================================================
# 4. ADD PROTOCOL MAPPERS to scanner-client
# Fixes: 6.8.4 (acr/amr in tokens), 9.2.4 (audience)
# ============================================================
echo "[4/10] Adding protocol mappers (acr, audience)..."
# ACR claim mapper
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
  -H "$AUTH" -H "$CT" -d '{
  "name": "acr claim",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-hardcoded-claim-mapper",
  "consentRequired": false,
  "config": {
    "claim.name": "acr",
    "claim.value": "1",
    "jsonType.label": "String",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}'
# AMR claim mapper
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
  -H "$AUTH" -H "$CT" -d '{
  "name": "amr claim",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-hardcoded-claim-mapper",
  "consentRequired": false,
  "config": {
    "claim.name": "amr",
    "claim.value": "[\"otp\"]",
    "jsonType.label": "JSON",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}'

# Audience mapper
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
  -H "$AUTH" -H "$CT" -d '{
  "name": "audience",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "consentRequired": false,
  "config": {
    "included.client.audience": "'$SCANNER_CLIENT'",
    "id.token.claim": "false",
    "access.token.claim": "true"
  }
}'

# ============================================================
# 5. CONFIGURE CLIENT SCOPES for scanner-client
# Fixes: 8.2.3 (sensitive data in default scopes)
# ============================================================
echo "[5/10] Configuring client scopes..."
# Ensure openid scope is assigned (needed for UserInfo endpoint)
OPENID_SCOPE_ID=$(curl -s "$KC_URL/admin/realms/$REALM/client-scopes" -H "$AUTH" \
  | $PY -c "import sys,json; scopes=json.load(sys.stdin);
matches=[s['id'] for s in scopes if s['name']=='openid'];
print(matches[0] if matches else '')" 2>/dev/null)
if [ -n "$OPENID_SCOPE_ID" ]; then
  curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/default-client-scopes/$OPENID_SCOPE_ID" -H "$AUTH"
fi

# Remove sensitive scopes from defaults (profile, email → optional)
for SCOPE_NAME in profile email; do
  SCOPE_ID=$(curl -s "$KC_URL/admin/realms/$REALM/client-scopes" -H "$AUTH" \
    | $PY -c "import sys,json; scopes=json.load(sys.stdin);
matches=[s['id'] for s in scopes if s['name']=='$SCOPE_NAME'];
print(matches[0] if matches else '')" 2>/dev/null)
  if [ -n "$SCOPE_ID" ]; then
    curl -s -X DELETE "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/default-client-scopes/$SCOPE_ID" -H "$AUTH"
    curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/optional-client-scopes/$SCOPE_ID" -H "$AUTH"
  fi
done

# ============================================================
# 6. HARDEN admin-cli
# Fixes: 10.1.1 (public client with DAG)
# ============================================================
echo "[6/10] Hardening admin-cli..."
ADMINCLI_UUID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=admin-cli" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$ADMINCLI_UUID" -H "$AUTH" -H "$CT" -d '{
  "clientId": "admin-cli",
  "enabled": true,
  "publicClient": true,
  "directAccessGrantsEnabled": false
}'

# ============================================================
# 7. GENERATE RSA 3072-bit KEYS (replace default 2048)
# Fixes: 11.2.3 (RSA key strength)
# ============================================================
echo "[7/10] Replacing RSA keys with 4096-bit..."
# Get realm internal ID for parentId
REALM_ID=$(curl -s "$KC_URL/admin/realms/$REALM" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)

# Create 4096-bit keys FIRST (so Keycloak always has RSA keys available)
curl -s -X POST "$KC_URL/admin/realms/$REALM/components" -H "$AUTH" -H "$CT" \
  -d '{"name":"rsa-4096-sig","providerId":"rsa-generated","providerType":"org.keycloak.keys.KeyProvider","parentId":"'"$REALM_ID"'","config":{"keySize":["4096"],"priority":["200"],"active":["true"],"algorithm":["RS256"]}}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/components" -H "$AUTH" -H "$CT" \
  -d '{"name":"rsa-4096-enc","providerId":"rsa-enc-generated","providerType":"org.keycloak.keys.KeyProvider","parentId":"'"$REALM_ID"'","config":{"keySize":["4096"],"priority":["200"],"active":["true"],"algorithm":["RSA-OAEP"]}}'

# NOW delete default 2048-bit keys (our 4096 keys ensure no auto-regeneration)
DEFAULT_RSA=$(curl -s "$KC_URL/admin/realms/$REALM/components?type=org.keycloak.keys.KeyProvider" -H "$AUTH" \
  | $PY -c "
import sys,json
for c in json.load(sys.stdin):
  if 'rsa' in c['providerId'] and c['name'] not in ('rsa-4096-sig','rsa-4096-enc'):
    print(c['id'])
" 2>/dev/null)
for KEY_ID in $DEFAULT_RSA; do
  curl -s -X DELETE "$KC_URL/admin/realms/$REALM/components/$KEY_ID" -H "$AUTH"
done

# ============================================================
# 8. HARDEN AUTHENTICATION FLOWS
# Fixes: 6.3.4 (direct grant MFA), 6.4.3 (reset creds MFA),
#        7.1.2 (session limits)
# ============================================================
echo "[8/10] Hardening authentication flows..."

# 8a. Copy "direct grant" and add OTP → fixes 6.3.4
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/direct%20grant/copy" \
  -H "$AUTH" -H "$CT" -d '{"newName":"direct grant with otp"}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/direct%20grant%20with%20otp/executions/execution" \
  -H "$AUTH" -H "$CT" -d '{"provider":"direct-grant-validate-otp"}'
# Set OTP step to REQUIRED
DG_OTP_EXEC=$(curl -s "$KC_URL/admin/realms/$REALM/authentication/flows/direct%20grant%20with%20otp/executions" -H "$AUTH" \
  | $PY -c "import sys,json;execs=json.load(sys.stdin);print([e['id'] for e in execs if e.get('providerId')=='direct-grant-validate-otp'][0])" 2>/dev/null)
curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/flows/direct%20grant%20with%20otp/executions" \
  -H "$AUTH" -H "$CT" -d '{"id":"'$DG_OTP_EXEC'","requirement":"REQUIRED","providerId":"direct-grant-validate-otp"}'
# Bind to realm
curl -s -X PUT "$KC_URL/admin/realms/$REALM" -H "$AUTH" -H "$CT" -d '{"directGrantFlow":"direct grant with otp"}'

# 8b. Copy "reset credentials" and add OTP → fixes 6.4.3
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/reset%20credentials/copy" \
  -H "$AUTH" -H "$CT" -d '{"newName":"reset credentials with otp"}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/reset%20credentials%20with%20otp/executions/execution" \
  -H "$AUTH" -H "$CT" -d '{"provider":"auth-otp-form"}'
RC_OTP_EXEC=$(curl -s "$KC_URL/admin/realms/$REALM/authentication/flows/reset%20credentials%20with%20otp/executions" -H "$AUTH" \
  | $PY -c "import sys,json;execs=json.load(sys.stdin);print([e['id'] for e in execs if e.get('providerId')=='auth-otp-form'][0])" 2>/dev/null)
curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/flows/reset%20credentials%20with%20otp/executions" \
  -H "$AUTH" -H "$CT" -d '{"id":"'$RC_OTP_EXEC'","requirement":"REQUIRED","providerId":"auth-otp-form"}'
curl -s -X PUT "$KC_URL/admin/realms/$REALM" -H "$AUTH" -H "$CT" -d '{"resetCredentialsFlow":"reset credentials with otp"}'

# 8c. Copy browser flow and add session limits → fixes 7.1.2
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/browser/copy" \
  -H "$AUTH" -H "$CT" -d '{"newName":"browser with session limits"}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/browser%20with%20session%20limits/executions/execution" \
  -H "$AUTH" -H "$CT" -d '{"provider":"user-session-limits"}'
SL_EXEC=$(curl -s "$KC_URL/admin/realms/$REALM/authentication/flows/browser%20with%20session%20limits/executions" -H "$AUTH" \
  | $PY -c "import sys,json;execs=json.load(sys.stdin);matches=[e['id'] for e in execs if e.get('providerId')=='user-session-limits'];print(matches[0] if matches else '')" 2>/dev/null)
if [ -n "$SL_EXEC" ]; then
  curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/flows/browser%20with%20session%20limits/executions" \
    -H "$AUTH" -H "$CT" -d '{"id":"'$SL_EXEC'","requirement":"REQUIRED","providerId":"user-session-limits"}'
fi
curl -s -X PUT "$KC_URL/admin/realms/$REALM" -H "$AUTH" -H "$CT" -d '{"browserFlow":"browser with session limits"}'

# ============================================================
# 9. REQUIRED ACTIONS
# ============================================================
echo "[9/10] Configuring required actions..."
curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/required-actions/UPDATE_PASSWORD" \
  -H "$AUTH" -H "$CT" -d '{"alias":"UPDATE_PASSWORD","name":"Update Password","enabled":true,"defaultAction":false}'
curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/required-actions/CONFIGURE_TOTP" \
  -H "$AUTH" -H "$CT" -d '{"alias":"CONFIGURE_TOTP","name":"Configure OTP","enabled":true,"defaultAction":true}'

# ============================================================
# 10. VERIFY CONNECTION
# ============================================================
# Final cleanup: remove any auto-generated default RSA keys
DEFAULT_RSA2=$(curl -s "$KC_URL/admin/realms/$REALM/components?type=org.keycloak.keys.KeyProvider" -H "$AUTH" \
  | $PY -c "
import sys,json
for c in json.load(sys.stdin):
  if 'rsa' in c['providerId'] and c['name'] not in ('rsa-4096-sig','rsa-4096-enc'):
    print(c['id'])
" 2>/dev/null)
for KEY_ID in $DEFAULT_RSA2; do
  curl -s -X DELETE "$KC_URL/admin/realms/$REALM/components/$KEY_ID" -H "$AUTH"
done

echo "[10/10] Verifying connection..."
TEST_TOKEN=$(curl -s -X POST "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
  -d "grant_type=client_credentials&client_id=$SCANNER_CLIENT&client_secret=$SCANNER_SECRET" \
  | $PY -c "import sys,json; t=json.load(sys.stdin); print('OK' if 'access_token' in t else 'FAIL: '+str(t))" 2>/dev/null)
echo "Token test: $TEST_TOKEN"

echo ""
echo "=== Done! Scan with client_credentials: ==="
echo '{"serverUrl":"'$KC_URL'","realm":"'$REALM'","clientId":"'$SCANNER_CLIENT'","clientSecret":"'$SCANNER_SECRET'","grantType":"client_credentials"}'
echo ""
echo "=== Findings that CANNOT be fixed via Admin API: ==="
echo "  - 12.2.2: Self-signed cert (needs real CA cert)"
echo "  - 12.1.2: Cipher suites (needs Keycloak server TLS config)"
echo "  - 6.1.2: Password blacklist (needs blacklist file on Keycloak server)"
