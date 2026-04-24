#!/usr/bin/env bash

set -e -o pipefail

OPENSEARCH_MAIN_CLASS=org.opensearch.security.tools.SecurityAdmin \
  OPENSEARCH_ADDITIONAL_CLASSPATH_DIRECTORIES=plugins/opensearch-security:plugins/opensearch-security/deps \
  "`dirname "$0"`/../bin/opensearch-cli" \
  "$@"