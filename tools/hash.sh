#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

BIN_PATH="java"

if [ -z "$JAVA_HOME" ]; then
    echo "WARNING: JAVA_HOME not set, will use $(which $BIN_PATH)"
else
    BIN_PATH="$JAVA_HOME/bin/java"
fi

"$BIN_PATH" $JAVA_OPTS -cp "$DIR/../../opendistro_security_ssl/*:$DIR/../*:$DIR/../deps/*:$DIR/../../../lib/*" com.amazon.opendistroforelasticsearch.security.tools.Hasher "$@"