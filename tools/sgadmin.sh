#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
java $JAVA_OPTS -Dlog4j.configurationFile="$DIR/../../../config/log4j2.properties" -cp "$DIR/../*:$DIR/../../../lib/*" com.floragunn.searchguard.tools.SearchGuardAdmin "$@"