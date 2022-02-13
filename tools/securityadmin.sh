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

BIN_PATH="java"

# now set the path to java: first OPENSEARCH_JAVA_HOME, then JAVA_HOME
if [ ! -z "$OPENSEARCH_JAVA_HOME" ]; then
    BIN_PATH="$OPENSEARCH_JAVA_HOME/bin/java"
elif [ ! -z "$JAVA_HOME" ]; then
    BIN_PATH="$JAVA_HOME/bin/java"
else
    echo "WARNING: nor OPENSEARCH_JAVA_HOME nor JAVA_HOME is set, will use $(which $BIN_PATH)"
fi

"$BIN_PATH" $JAVA_OPTS -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "$DIR/../*:$DIR/../../../lib/*:$DIR/../deps/*" org.opensearch.security.tools.SecurityAdmin "$@" 2>/dev/null

