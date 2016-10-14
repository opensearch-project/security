#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
java $JAVA_OPTS -cp "$DIR/../*:$DIR/../../../lib/*:$DIR/../../../config/log4j2.properties" com.floragunn.searchguard.tools.SearchGuardAdmin "$@"