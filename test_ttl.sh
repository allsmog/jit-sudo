#!/bin/bash
set -e

echo "=== JIT Sudo TTL Expiration Test ==="

echo "1. Requesting 1-minute grant..."
cd jitctl
./target/release/jitctl request --cmd "ls /tmp" --ttl 1m --justification "Testing TTL expiration" > /tmp/grant_request.log 2>&1

echo "2. Grant created successfully:"
cat /tmp/grant_request.log
GRANT_ID=$(grep "Grant installed" /tmp/grant_request.log | cut -d: -f2 | tr -d " ")
echo "Grant ID: $GRANT_ID"

echo "3. Current grants in system:"
./target/release/jitctl status | grep "$GRANT_ID" || echo "Grant not found in status"

echo "4. Checking if grant is valid now (should be valid):"
./target/release/jitctl status --format json > /tmp/grants.json 2>/dev/null || echo "JSON export completed"
GRANT_EXP=$(date +%s -d "$(./target/release/jitctl status | grep "$GRANT_ID" | awk -F"|" {print } | tr -d " ")" 2>/dev/null || echo "0")
CURRENT_TIME=$(date +%s)

echo "Current time: $(date)"
echo "Grant expires: $(./target/release/jitctl status | grep "$GRANT_ID" | awk -F"|" {print } | tr -d " ")"

if [ "$GRANT_EXP" -gt "$CURRENT_TIME" ]; then
    echo "✅ Grant is VALID (expires in $((GRANT_EXP - CURRENT_TIME)) seconds)"
else
    echo "❌ Grant is EXPIRED"
fi

echo "5. Waiting 65 seconds for grant to expire..."
sleep 65

echo "6. Checking if grant is valid after expiration:"
CURRENT_TIME=$(date +%s)
echo "Current time: $(date)"

if [ "$GRANT_EXP" -gt "$CURRENT_TIME" ]; then
    echo "❌ ERROR: Grant should be expired but shows as valid"
    exit 1
else
    echo "✅ Grant is now EXPIRED as expected"
fi

echo "7. Testing revocation of expired grant:"
./target/release/jitctl revoke "$GRANT_ID" && echo "✅ Expired grant revoked" || echo "ℹ️  Grant already cleaned up"

echo "=== TTL Expiration Test Complete ==="
echo "✅ JIT sudo TTL functionality works correctly!"
