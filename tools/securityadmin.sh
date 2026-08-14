#!/usr/bin/env bash

set -e -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Forward JAVA_OPTS into OPENSEARCH_JAVA_OPTS for backward compatibility
OPENSEARCH_JAVA_OPTS="${JAVA_OPTS:+${JAVA_OPTS} }${OPENSEARCH_JAVA_OPTS}"

OPENSEARCH_MAIN_CLASS=org.opensearch.security.tools.SecurityAdmin \
  OPENSEARCH_ADDITIONAL_CLASSPATH_DIRECTORIES=plugins/opensearch-security \
  OPENSEARCH_JAVA_OPTS="$OPENSEARCH_JAVA_OPTS" \
  "${SCRIPT_DIR}/../../../bin/opensearch-cli" \
  "$@"
