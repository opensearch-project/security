#!/bin/bash

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

PLUGIN_DIR="$OPENSEARCH_HOME/plugins/opensearch-security"

BIN_PATH="java"

# now set the path to java: first OPENSEARCH_JAVA_HOME, then JAVA_HOME
if [ ! -z "$OPENSEARCH_JAVA_HOME" ]; then
    BIN_PATH="$OPENSEARCH_JAVA_HOME/bin/java"
elif [ ! -z "$JAVA_HOME" ]; then
    BIN_PATH="$JAVA_HOME/bin/java"
else
    echo "WARNING: nor OPENSEARCH_JAVA_HOME nor JAVA_HOME is set, will use $(which $BIN_PATH)"
fi

"$BIN_PATH" $JAVA_OPTS -cp "$PLUGIN_DIR/*:$PLUGIN_DIR/deps/*:$OPENSEARCH_HOME/lib/*" org.opensearch.security.tools.Hasher "$@"
