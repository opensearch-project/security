#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
java $JAVA_OPTS -cp "$DIR/../../search-guard-ssl/*:$DIR/../*:$DIR/../deps/*:$DIR/../../../lib/*" com.floragunn.searchguard.tools.SearchGuardAdmin "$@"