#!/bin/bash
#install_demo_configuration.sh [-y]

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
if [ -n "$OPENSEARCH_JAVA_HOME" ]; then
    BIN_PATH="$OPENSEARCH_JAVA_HOME/bin/java"
elif [ -n "$JAVA_HOME" ]; then
    BIN_PATH="$JAVA_HOME/bin/java"
else
    echo "Unable to find java runtime"
    echo "OPENSEARCH_JAVA_HOME or JAVA_HOME must be defined"
    exit 1
fi

"$BIN_PATH" $JAVA_OPTS -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "$DIR/../*:$DIR/../../../lib/*:$DIR/../deps/*" org.opensearch.security.tools.democonfig.Installer "$DIR" "$@" 2>/dev/null
