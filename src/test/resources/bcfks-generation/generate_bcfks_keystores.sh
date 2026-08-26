#!/usr/bin/env bash
#
# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Generates BCFKS counterparts for every JKS / PKCS12 keystore under
# src/test/resources/.  See README.md for usage and prerequisites.

set -euo pipefail

if [[ -z "${BC_FIPS_JAR:-}" ]]; then
  echo "ERROR: BC_FIPS_JAR is not set. Point it to the bc-fips-*.jar, e.g.:" >&2
  echo "  export BC_FIPS_JAR=/path/to/bc-fips-2.1.2.jar" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES="$(cd "$SCRIPT_DIR/.." && pwd)"
BC_FIPS="$BC_FIPS_JAR"

CONVERTED=0

convert() {
  local src="$1"
  local type="$2"   # JKS | PKCS12
  local pass="${3:-changeit}"
  local dest="${src%.*}.bcfks"
  java --enable-native-access=ALL-UNNAMED \
       -cp "$BC_FIPS" \
       "$SCRIPT_DIR/ConvertKeystore.java" "$src" "$type" "$pass" "$dest" "$pass"
  CONVERTED=$(( CONVERTED + 1 ))
}

# ── JKS-only keystores (no PKCS12 counterpart exists) ────────────────────────

JKS_ONLY=(
  cache/kirk-keystore.jks
  cache/node-0-keystore.jks
  cache/spock-keystore.jks
  cache/truststore.jks

  dlsfls/kirk-keystore.jks
  dlsfls/node-0-keystore.jks
  dlsfls/spock-keystore.jks
  dlsfls/truststore.jks

  jwt/kirk-keystore.jks
  jwt/node-0-keystore.jks
  jwt/spock-keystore.jks
  jwt/truststore.jks

  ldap/kirk-keystore.jks
  ldap/node-0-keystore.jks
  ldap/spock-keystore.jks
  ldap/truststore.jks

  migration/kirk-keystore.jks
  migration/node-0-keystore.jks
  migration/spock-keystore.jks
  migration/truststore.jks

  multitenancy/kirk-keystore.jks
  multitenancy/node-0-keystore.jks
  multitenancy/spock-keystore.jks
  multitenancy/truststore.jks

  restapi/kirk-keystore.jks
  restapi/node-0-keystore.jks
  restapi/spock-keystore.jks
  restapi/truststore.jks

  sanity-tests/kirk-keystore.jks

  ssl/extended_key_usage/node-0-keystore.jks
  ssl/extended_key_usage/truststore.jks

  ssl/reload/kirk-keystore.jks
  ssl/reload/spock-keystore.jks
  ssl/reload/truststore.jks

  ssl/truststore.jks
  ssl/truststore_fail.jks
  ssl/truststore_invalid.jks
  ssl/truststore_valid.jks

  # sslConfigurator keystores use password 'secret' – passed explicitly below

  kirk-keystore.jks
  node-0-keystore.jks
  node-1-keystore.jks
  node-2-keystore.jks
  spock-keystore.jks
  truststore.jks
  truststore_fail.jks

  # auditlog/ JKS files intentionally omitted: PKCS12 counterparts exist
  auditlog/truststore.jks
  auditlog/truststore_fail.jks
)

echo "=== Converting JKS-only keystores ==="
for rel in "${JKS_ONLY[@]}"; do
  [[ "$rel" =~ ^# ]] && continue
  convert "$RESOURCES/$rel" JKS
done

# ── PKCS12 keystores (preferred source when JKS counterpart also exists) ─────
#
# For the pairs listed in the header comment the BCFKS file is produced
# exclusively from the PKCS12 source; the JKS files are deliberately skipped.

P12_FILES=(
  # auditlog/ – PKCS12 preferred over JKS counterparts
  auditlog/kirk-keystore.p12
  auditlog/node-0-keystore.p12
  auditlog/spock-keystore.p12

  # ssl/ – PKCS12 preferred over JKS counterparts
  ssl/kirk-keystore.p12
  ssl/node-0-keystore.p12
  ssl/node-1-keystore.p12
  ssl/node-2-keystore.p12
  ssl/spock-keystore.p12

  # ssl/ – PKCS12-only (no JKS counterpart)
  ssl/node-untspec5-keystore.p12

  # root-level – PKCS12-only
  node-untspec5-keystore.p12
  node-untspec6-keystore.p12
)

echo ""
echo "=== Converting PKCS12 keystores (preferred source for shared base names) ==="
for rel in "${P12_FILES[@]}"; do
  [[ "$rel" =~ ^# ]] && continue
  convert "$RESOURCES/$rel" PKCS12
done

# ── sslConfigurator keystores (password: 'secret', not 'changeit') ───────────
#
# These keystores were generated with a different password.  They are listed
# separately so the non-default password is explicit rather than buried in the
# arrays above.

echo ""
echo "=== Converting sslConfigurator keystores (password: secret) ==="
for rel in \
  sslConfigurator/jks/node1-keystore.jks \
  sslConfigurator/jks/other-root-ca.jks \
  sslConfigurator/jks/truststore.jks \
  sslConfigurator/pem/node-wrong-hostname-keystore.jks \
  sslConfigurator/pem/node1-keystore.jks \
  sslConfigurator/pem/truststore.jks
do
  convert "$RESOURCES/$rel" JKS secret
done

echo ""
echo "Done. $CONVERTED BCFKS files written alongside their source keystores."
