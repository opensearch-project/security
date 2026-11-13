#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -e -o pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
if ! [ -x "$(command -v realpath)" ]; then
    if [ -L "$SCRIPT_PATH" ]; then

        [ -x "$(command -v readlink)" ] || { echo "Not able to resolve symlink. Install realpath or readlink.";exit 1; }

        # try readlink (-f not needed because we know its a symlink)
        DIR="$( cd "$( dirname $(readlink "$SCRIPT_PATH") )" && pwd -P)"
    else
        DIR="$( cd "$( dirname "$SCRIPT_PATH" )" && pwd -P)"
    fi
else
    DIR="$( cd "$( dirname "$(realpath "$SCRIPT_PATH")" )" && pwd -P)"
fi

if [ -z "$OPENSEARCH_HOME" ]; then
  OPENSEARCH_HOME="$DIR"
  while [ "$OPENSEARCH_HOME" != "/" ] && [ -z "$(ls "$OPENSEARCH_HOME/lib/opensearch-"*.jar 2>/dev/null)" ]; do
    OPENSEARCH_HOME="$(dirname "$OPENSEARCH_HOME")"
  done
  if [ "$OPENSEARCH_HOME" = "/" ]; then
    echo "Could not locate OpenSearch home. Set OPENSEARCH_HOME manually." >&2
    exit 1
  fi
fi

CALLER_DIR="$PWD"

# Forward JAVA_OPTS into OPENSEARCH_JAVA_OPTS for backward compatibility
OPENSEARCH_JAVA_OPTS="${JAVA_OPTS:+${JAVA_OPTS} }${OPENSEARCH_JAVA_OPTS}"
unset JAVA_OPTS

# Core launcher environment: java lookup and version check, OPENSEARCH_PATH_CONF and,
# with OPENSEARCH_FIPS_MODE=true, the FIPS JVM options. It ends with `cd "$OPENSEARCH_HOME"`;
# return to the caller's directory so relative -cd/-f/-backup paths resolve as documented.
source "$OPENSEARCH_HOME/bin/opensearch-env"
cd "$CALLER_DIR"

exec "$JAVA" "$XSHARE" -Xms4m -Xmx64m -XX:+UseSerialGC $OPENSEARCH_JAVA_OPTS \
  -Dopensearch.path.home="$OPENSEARCH_HOME" \
  -Dopensearch.path.conf="$OPENSEARCH_PATH_CONF" \
  -Dopensearch.distribution.type="$OPENSEARCH_DISTRIBUTION_TYPE" \
  -cp "$OPENSEARCH_CLASSPATH:$OPENSEARCH_HOME/plugins/opensearch-security/*" \
  org.opensearch.security.tools.SecurityAdmin "$@"
