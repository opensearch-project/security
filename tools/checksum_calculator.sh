#!/bin/bash

# Determine the script directory
SCRIPT_PATH="${BASH_SOURCE[0]}"
if [ -L "$SCRIPT_PATH" ]; then
    if [ -x "$(command -v readlink)" ]; then
        DIR="$(cd "$(dirname "$(readlink "$SCRIPT_PATH")")" && pwd -P)"
    else
        echo "Not able to resolve symlink. Install readlink."
        exit 1
    fi
else
    DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd -P)"
fi

# Set the default Java binary path
BIN_PATH="java"

# Check for OPENSEARCH_JAVA_HOME and JAVA_HOME
if [ ! -z "$OPENSEARCH_JAVA_HOME" ]; then
    BIN_PATH="$OPENSEARCH_JAVA_HOME/bin/java"
elif [ ! -z "$JAVA_HOME" ]; then
    BIN_PATH="$JAVA_HOME/bin/java"
else
    echo "WARNING: Neither OPENSEARCH_JAVA_HOME nor JAVA_HOME is set, will use $(which $BIN_PATH)"
fi

# Execute the Java class
"$BIN_PATH" $JAVA_OPTS -cp "$DIR/../../opendistro_security_ssl/*:$DIR/../*:$DIR/../deps/*:$DIR/../../../lib/*" org.opensearch.security.tools.ChecksumCalculator "$@"
