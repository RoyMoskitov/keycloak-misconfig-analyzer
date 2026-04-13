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

echo "=== Setting up MAXIMALLY VULNERABLE realm '$REALM' on $KC_URL ==="

TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$ADMIN&password=$PASS" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$TOKEN" ]; then echo "ERROR: Failed to get admin token"; exit 1; fi

AUTH="Authorization: Bearer $TOKEN"
CT="Content-Type: application/json"

# ============================================================
# 1. CREATE REALM — максимально небезопасные настройки
# Triggers: 6.3.1 (brute force OFF + permanentLockout),
#   6.3.5 (events OFF), 6.2.1 (short password), 6.2.9 (short maxLength),
#   6.2.5 (composition rules), 6.2.10 (forced rotation),
#   6.1.2 (no blacklist), 11.4.3 (low iterations),
#   7.2.4 (no refresh rotation), 7.3.1 (no session timeout),
#   7.1.3 (no session limits), 7.6.1 (no session config),
#   10.4.8 (no offline max lifespan), 10.4.3 (long code lifespan),
#   7.2.1 (long access token), 7.4.3 (no session invalidation),
#   6.4.1 (long action tokens, registration without email verify),
#   6.8.1 (duplicate emails allowed)
# ============================================================
echo "[1/12] Creating realm with vulnerable settings..."
curl -s -X POST "$KC_URL/admin/realms" -H "$AUTH" -H "$CT" -d '{
  "realm": "'$REALM'",
  "enabled": true,
  "registrationAllowed": true,
  "verifyEmail": false,
  "duplicateEmailsAllowed": true,
  "loginWithEmailAllowed": true,
  "resetPasswordAllowed": true,
  "sslRequired": "NONE",
  "bruteForceProtected": false,
  "permanentLockout": true,
  "failureFactor": 100,
  "waitIncrementSeconds": 5,
  "maxFailureWaitSeconds": 30,
  "maxDeltaTimeSeconds": 60,
  "minimumQuickLoginWaitSeconds": 0,
  "quickLoginCheckMilliSeconds": 0,
  "revokeRefreshToken": false,
  "refreshTokenMaxReuse": 10,
  "ssoSessionIdleTimeout": 0,
  "ssoSessionMaxLifespan": 0,
  "accessTokenLifespan": 7200,
  "accessCodeLifespan": 3600,
  "accessCodeLifespanLogin": 7200,
  "offlineSessionMaxLifespanEnabled": false,
  "actionTokenGeneratedByAdminLifespan": 86400,
  "actionTokenGeneratedByUserLifespan": 86400,
  "eventsEnabled": false,
  "adminEventsEnabled": false,
  "adminEventsDetailsEnabled": false,
  "passwordPolicy": "length(4) and maxLength(20) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)"
}'

# ============================================================
# 2. WEAK OTP POLICY
# Triggers: 6.5.1 (HOTP instead of TOTP), 6.5.4 (4 digits),
#   6.5.5 (long period + few digits), 6.6.3 (no brute force = no OTP rate limit)
# ============================================================
echo "[2/12] Setting weak OTP policy + Remember Me..."
curl -s -X PUT "$KC_URL/admin/realms/$REALM" -H "$AUTH" -H "$CT" -d '{
  "otpPolicyType": "hotp",
  "otpPolicyAlgorithm": "HmacSHA1",
  "otpPolicyDigits": 4,
  "otpPolicyPeriod": 120,
  "otpPolicyLookAheadWindow": 10,
  "rememberMe": true,
  "ssoSessionMaxLifespanRememberMe": 2592000
}'

# ============================================================
# 3. VULNERABLE PUBLIC CLIENT (SPA)
# Triggers: 10.4.1 (wildcard redirect), 10.4.4 (implicit+DAG),
#   10.2.1 (no PKCE), 10.1.1 (public+DAG+refresh), 10.7.1 (no consent),
#   10.4.11 (fullScope), 8.4.1 (fullScope), 8.2.1 (public no scopes),
#   3.4.2 (CORS *), 10.4.2 (implicit instead of standard)
# ============================================================
echo "[3/12] Creating vulnerable public client..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "vulnerable-spa",
  "enabled": true,
  "publicClient": true,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "consentRequired": false,
  "fullScopeAllowed": true,
  "redirectUris": ["*"],
  "webOrigins": ["*"],
  "attributes": {
    "use.refresh.tokens": "true",
    "access.token.lifespan": "86400"
  }
}'

# Add sensitive protocol mappers to SPA client → 8.2.3
SPA_UUID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=vulnerable-spa" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)

# Also add authorization claims to ID token → 9.2.2 (token type confusion)
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients/$SPA_UUID/protocol-mappers/models" \
  -H "$AUTH" -H "$CT" -d '{
  "name": "realm-roles-in-idtoken",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-realm-role-mapper",
  "config": {
    "claim.name": "realm_access.roles",
    "jsonType.label": "String",
    "multivalued": "true",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "false"
  }
}'

for ATTR in email phone_number address birthdate; do
  curl -s -X POST "$KC_URL/admin/realms/$REALM/clients/$SPA_UUID/protocol-mappers/models" \
    -H "$AUTH" -H "$CT" -d '{
    "name": "'$ATTR' mapper",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": {
      "user.attribute": "'$ATTR'",
      "claim.name": "'$ATTR'",
      "jsonType.label": "String",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "userinfo.token.claim": "true"
    }
  }'
done

# ============================================================
# 4. VULNERABLE CONFIDENTIAL CLIENT
# Triggers: 10.4.4 (implicit+DAG on confidential), 10.4.1 (HTTP redirects),
#   7.2.2 (service account + long token), 10.4.10 (weak auth),
#   8.3.1 (no explicit algorithm)
# ============================================================
echo "[4/12] Creating vulnerable confidential client..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "vulnerable-backend",
  "enabled": true,
  "publicClient": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true,
  "consentRequired": false,
  "fullScopeAllowed": true,
  "secret": "weak-secret",
  "redirectUris": ["http://evil.example.com/*", "http://attacker.com/*", "http://localhost/*"],
  "webOrigins": ["*"],
  "attributes": {
    "access.token.lifespan": "86400",
    "access.token.signed.response.alg": "HS256"
  }
}'

# Client with JWKS URL over HTTP → 9.1.3 (untrusted key source)
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "jwt-auth-client",
  "enabled": true,
  "publicClient": false,
  "standardFlowEnabled": true,
  "serviceAccountsEnabled": true,
  "clientAuthenticatorType": "client-jwt",
  "redirectUris": ["https://app.example.com/*"],
  "attributes": {
    "use.jwks.url": "true",
    "jwks.url": "http://untrusted.example.com/keys/jwks.json",
    "token.endpoint.auth.signing.alg": "RS256"
  }
}'

# ============================================================
# 5. MORE PROBLEMATIC CLIENTS
# Triggers: 10.4.2 (implicit-only), 10.6.2 (frontchannel logout),
#   10.7.2 (consent without name/description), 10.4.7 (many clients)
# ============================================================
echo "[5/12] Creating additional problematic clients..."

# Implicit-only client
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "implicit-only-client",
  "enabled": true,
  "publicClient": true,
  "standardFlowEnabled": false,
  "implicitFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "consentRequired": false,
  "fullScopeAllowed": true,
  "redirectUris": ["https://example.com/*"]
}'

# Frontchannel logout client → 10.6.2
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "logout-vulnerable",
  "enabled": true,
  "publicClient": false,
  "standardFlowEnabled": true,
  "frontchannelLogout": true,
  "consentRequired": true,
  "fullScopeAllowed": true,
  "redirectUris": ["http://anywhere.com/*"],
  "attributes": {
    "post.logout.redirect.uris": "http://anywhere.com"
  }
}'

# Consent client without name/description → 10.7.2
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "no-description-client",
  "enabled": true,
  "publicClient": true,
  "standardFlowEnabled": true,
  "consentRequired": true,
  "fullScopeAllowed": true,
  "redirectUris": ["https://example.com/*"]
}'

# Disabled but not removed client
curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
  "clientId": "old-unused-client",
  "enabled": false,
  "publicClient": false,
  "fullScopeAllowed": true
}'

# Bulk clients to trigger 10.4.7 (>20 user clients)
for i in $(seq 1 20); do
  curl -s -X POST "$KC_URL/admin/realms/$REALM/clients" -H "$AUTH" -H "$CT" -d '{
    "clientId": "bulk-client-'$i'",
    "enabled": true,
    "publicClient": true,
    "standardFlowEnabled": true,
    "implicitFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "consentRequired": false,
    "fullScopeAllowed": true,
    "redirectUris": ["*"]
  }'
done

# ============================================================
# 6. DISABLE REQUIRED ACTIONS (before creating users!)
# Triggers: 6.4.2 (no modern MFA actions), 6.2.2 (no UPDATE_PASSWORD)
# ============================================================
# Refresh admin token (may have expired)
TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$ADMIN&password=$PASS" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
AUTH="Authorization: Bearer $TOKEN"

echo "[6/12] Disabling required actions..."
for ACTION in UPDATE_PASSWORD CONFIGURE_TOTP VERIFY_PROFILE UPDATE_PROFILE VERIFY_EMAIL; do
  curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/required-actions/$ACTION" \
    -H "$AUTH" -H "$CT" -d '{"alias":"'$ACTION'","enabled":false}'
done

# ============================================================
# 7. DEFAULT/WEAK USERS
# Triggers: 6.3.2 (default accounts), 6.2.3 (forced password update)
# ============================================================
echo "[6/12] Creating default/weak users..."
for U in admin test demo guest root operator; do
  curl -s -X POST "$KC_URL/admin/realms/$REALM/users" -H "$AUTH" -H "$CT" -d '{
    "username": "'$U'",
    "enabled": true,
    "credentials": [{"type": "password", "value": "Aa1!xxxx", "temporary": true}]
  }'
done

# User with stale temporary password
curl -s -X POST "$KC_URL/admin/realms/$REALM/users" -H "$AUTH" -H "$CT" -d '{
  "username": "stale-user",
  "enabled": true,
  "requiredActions": ["UPDATE_PASSWORD"],
  "credentials": [{"type": "password", "value": "Aa1!temp", "temporary": true}]
}'

# ============================================================
# 7. SCANNER USER (needs admin access to scan)
# ============================================================
echo "[7/12] Creating scanner user..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/users" -H "$AUTH" -H "$CT" -d '{
  "username": "scanner-admin",
  "enabled": true,
  "credentials": [{"type": "password", "value": "Sc@n1pass", "temporary": false}]
}'
SID=$(curl -s "$KC_URL/admin/realms/$REALM/users?username=scanner-admin" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
RMID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
AROLE=$(curl -s "$KC_URL/admin/realms/$REALM/clients/$RMID/roles/realm-admin" -H "$AUTH")
curl -s -X POST "$KC_URL/admin/realms/$REALM/users/$SID/role-mappings/clients/$RMID" \
  -H "$AUTH" -H "$CT" -d "[$AROLE]"
curl -s -X PUT "$KC_URL/admin/realms/$REALM/users/$SID" -H "$AUTH" -H "$CT" \
  -d '{"requiredActions":[]}'

# ============================================================
# 8. DISABLE ACCOUNT CONSOLE
# Triggers: 7.5.2 (no session visibility), 6.2.2 (no password change),
#   10.4.9 (no token revocation UI), 7.5.1 (no reauth for sensitive)
# ============================================================
echo "[8/12] Disabling account-console..."
ACID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=account-console" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
[ -n "$ACID" ] && curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$ACID" \
  -H "$AUTH" -H "$CT" -d '{"enabled":false}'

# Also disable account client
ACCID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=account" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
[ -n "$ACCID" ] && curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$ACCID" \
  -H "$AUTH" -H "$CT" -d '{"enabled":false}'

# ============================================================
# 9. IDENTITY PROVIDERS with trustEmail
# Triggers: 6.8.1 (IdP spoofing — trustEmail=true, multiple IdPs)
# ============================================================
echo "[9/12] Adding vulnerable Identity Providers..."
curl -s -X POST "$KC_URL/admin/realms/$REALM/identity-provider/instances" \
  -H "$AUTH" -H "$CT" -d '{
  "alias": "evil-idp",
  "providerId": "oidc",
  "enabled": true,
  "trustEmail": true,
  "config": {
    "clientId": "fake",
    "clientSecret": "fake",
    "authorizationUrl": "https://evil.example.com/auth",
    "tokenUrl": "https://evil.example.com/token",
    "trustEmail": "true"
  }
}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/identity-provider/instances" \
  -H "$AUTH" -H "$CT" -d '{
  "alias": "another-evil-idp",
  "providerId": "oidc",
  "enabled": true,
  "trustEmail": true,
  "config": {
    "clientId": "another",
    "clientSecret": "another",
    "authorizationUrl": "https://another-evil.example.com/auth",
    "tokenUrl": "https://another-evil.example.com/token",
    "trustEmail": "true"
  }
}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/identity-provider/instances" \
  -H "$AUTH" -H "$CT" -d '{
  "alias": "third-evil-idp",
  "providerId": "saml",
  "enabled": true,
  "trustEmail": true,
  "config": {
    "singleSignOnServiceUrl": "https://third-evil.example.com/sso",
    "trustEmail": "true"
  }
}'

# ============================================================
# 10. WEAKEN BROWSER SECURITY HEADERS
# Triggers: 3.4.3 (no CSP), 3.4.4 (no nosniff), 3.4.5 (unsafe-url referrer),
#           3.4.6 (no X-Frame-Options), 3.4.1 (no HSTS)
# ============================================================
# Refresh admin token
TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$ADMIN&password=$PASS" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
AUTH="Authorization: Bearer $TOKEN"

echo "[10/16] Weakening browser security headers..."
curl -s -X PUT "$KC_URL/admin/realms/$REALM" -H "$AUTH" -H "$CT" -d '{
  "browserSecurityHeaders": {
    "contentSecurityPolicy": "",
    "xContentTypeOptions": "",
    "xFrameOptions": "",
    "referrerPolicy": "unsafe-url",
    "strictTransportSecurity": "",
    "contentSecurityPolicyReportOnly": "",
    "xRobotsTag": ""
  }
}'
echo "  Cleared CSP, X-Frame-Options, X-Content-Type-Options, HSTS; set Referrer-Policy=unsafe-url"

# ============================================================
# 10b. DELETE CONFIGURE_TOTP REQUIRED ACTION (not just disable!)
# Triggers: 6.4.2 (no modern MFA methods available)
# ============================================================
echo "[10b/16] Deleting CONFIGURE_TOTP required action..."
curl -s -X DELETE "$KC_URL/admin/realms/$REALM/authentication/required-actions/CONFIGURE_TOTP" -H "$AUTH"
# Also delete webauthn actions
curl -s -X DELETE "$KC_URL/admin/realms/$REALM/authentication/required-actions/webauthn-register" -H "$AUTH"
curl -s -X DELETE "$KC_URL/admin/realms/$REALM/authentication/required-actions/webauthn-register-passwordless" -H "$AUTH"
echo "  Deleted CONFIGURE_TOTP and WebAuthn required actions"

# ============================================================
# 11. ADD forceExpiredPasswordChange TO POLICY
# Triggers: 6.2.10 (forced password rotation = bad practice per NIST)
# ============================================================
echo "[11/14] Adding forced password rotation..."
curl -s -X PUT "$KC_URL/admin/realms/$REALM" -H "$AUTH" -H "$CT" -d '{
  "passwordPolicy": "length(4) and maxLength(20) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and forceExpiredPasswordChange(30)"
}'

# ============================================================
# 12. REMOVE ALL SCOPES FROM vulnerable-spa FIRST
# Triggers: 8.2.1 (public client without scopes/roles)
# ============================================================
echo "[12/14] Removing scopes from vulnerable-spa..."
ALL_SCOPES=$(curl -s "$KC_URL/admin/realms/$REALM/clients/$SPA_UUID/default-client-scopes" -H "$AUTH" \
  | $PY -c "import sys,json; [print(s['id']) for s in json.load(sys.stdin)]" 2>/dev/null)
for SCOPE_ID in $ALL_SCOPES; do
  curl -s -X DELETE "$KC_URL/admin/realms/$REALM/clients/$SPA_UUID/default-client-scopes/$SCOPE_ID" -H "$AUTH"
done
echo "  Removed all default scopes from vulnerable-spa"

# ============================================================
# 13. ADD offline_access TO DEFAULT SCOPES of bulk clients
# Triggers: 10.4.11 (offline_access in default scopes)
# ============================================================
# Refresh token before scope changes
TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$ADMIN&password=$PASS" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
AUTH="Authorization: Bearer $TOKEN"

echo "[13/14] Adding offline_access to bulk client default scopes..."
OFFLINE_SCOPE_ID=$(curl -s "$KC_URL/admin/realms/$REALM/client-scopes" -H "$AUTH" \
  | $PY -c "import sys,json; scopes=json.load(sys.stdin); matches=[s['id'] for s in scopes if s['name']=='offline_access']; print(matches[0] if matches else '')" 2>/dev/null)
if [ -n "$OFFLINE_SCOPE_ID" ]; then
  for i in $(seq 1 5); do
    BCID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=bulk-client-$i" -H "$AUTH" \
      | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
    if [ -n "$BCID" ]; then
      # Must remove from optional FIRST, then add to default (KC 26 API requirement)
      curl -s -X DELETE "$KC_URL/admin/realms/$REALM/clients/$BCID/optional-client-scopes/$OFFLINE_SCOPE_ID" -H "$AUTH"
      curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$BCID/default-client-scopes/$OFFLINE_SCOPE_ID" -H "$AUTH"
    fi
  done
  echo "  Added offline_access to bulk-client-1..5 default scopes"
fi

# ============================================================
# 14. ENSURE admin-cli HAS DIRECT ACCESS GRANTS
# Triggers: 10.1.1 (public + DAG on admin-cli)
# ============================================================
echo "[14/15] Keeping admin-cli with DAG enabled..."
ADMINCLI_UUID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=admin-cli" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$ADMINCLI_UUID" \
  -H "$AUTH" -H "$CT" -d '{
  "clientId": "admin-cli",
  "enabled": true,
  "publicClient": true,
  "directAccessGrantsEnabled": true,
  "fullScopeAllowed": true
}'

# ============================================================
# 15. VERIFY CONNECTION
# ============================================================
# Refresh admin token (may have expired during setup)
TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=$ADMIN&password=$PASS" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
AUTH="Authorization: Bearer $TOKEN"

# Reset scanner-admin password after policy change (forceExpiredPasswordChange blocks login)
SID=$(curl -s "$KC_URL/admin/realms/$REALM/users?username=scanner-admin" -H "$AUTH" \
  | $PY -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
curl -s -X PUT "$KC_URL/admin/realms/$REALM/users/$SID/reset-password" \
  -H "$AUTH" -H "$CT" -d '{"type":"password","value":"Sc@n1pass","temporary":false}'
curl -s -X PUT "$KC_URL/admin/realms/$REALM/users/$SID" \
  -H "$AUTH" -H "$CT" -d '{"requiredActions":[]}'

echo "[15/15] Verifying connection..."
TEST_TOKEN=$(curl -s -X POST "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=scanner-admin&password=Sc@n1pass" \
  | $PY -c "import sys,json; t=json.load(sys.stdin); print('OK' if 'access_token' in t else 'FAIL: '+str(t))" 2>/dev/null)
echo "Token test: $TEST_TOKEN"

# NOTE: Step 16 removed. Modifying authentication flow executions via
# Admin REST API in KC 26 causes AuthenticationFlowException.
# 6.3.4 check is redesigned to detect MFA-in-conditional-only as weakness.
# 6.6.2 OTP binding is safe with default config (no allow.reuse).

echo ""
echo "=== Done! Scan with: ==="
echo '{"serverUrl":"'$KC_URL'","realm":"'$REALM'","clientId":"admin-cli","username":"scanner-admin","password":"Sc@n1pass"}'
echo ""
echo "=== Expected: maximum DETECTED findings ==="
echo "  HTTP mode: TLS/cert checks will detect HTTP-only issues"
echo "  No brute force, no events, no MFA, weak passwords, weak OTP"
echo "  Wildcard redirects, implicit flow, no PKCE, no consent"
echo "  Multiple vulnerable IdPs with trustEmail"
echo "  Account console disabled, required actions disabled"
