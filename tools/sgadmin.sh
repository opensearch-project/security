#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
java $JAVA_OPTS -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "$DIR/../*:$DIR/../../../lib/*:$DIR/../deps/*" com.floragunn.searchguard.tools.SearchGuardAdmin "$@"