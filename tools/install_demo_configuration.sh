#!/bin/bash
#install_demo_configuration.sh [-y]

UNAME=$(uname -s)
if [ "$UNAME" = "FreeBSD" ]; then
  OS="freebsd"
elif [ "$UNAME" = "Darwin" ]; then
  OS="darwin"
else
  OS="other"
fi

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
  # move to opensearch root folder and set the variable
  OPENSEARCH_HOME=`cd "$DIR/../../.."; pwd`
fi

# now set the path to java: OPENSEARCH_JAVA_HOME -> JAVA_HOME -> bundled JRE -> bundled JDK
if [ -n "$OPENSEARCH_JAVA_HOME" ]; then
  JAVA="$OPENSEARCH_JAVA_HOME/bin/java"
  JAVA_TYPE="OPENSEARCH_JAVA_HOME"
elif [ -n "$JAVA_HOME" ]; then
  JAVA="$JAVA_HOME/bin/java"
  JAVA_TYPE="JAVA_HOME"
else
  if [ "$OS" = "darwin" ]; then
    # macOS bundled Java
    JAVA="$OPENSEARCH_HOME/jdk.app/Contents/Home/bin/java"
    JAVA_TYPE="bundled jdk"
  elif [ "$OS" = "freebsd" ]; then
    # using FreeBSD default java from ports if JAVA_HOME is not set
    JAVA="/usr/local/bin/java"
    JAVA_TYPE="bundled jdk"
  elif [ -d "$OPENSEARCH_HOME/jre" ]; then
    JAVA="$OPENSEARCH_HOME/jre/bin/java"
    JAVA_TYPE="bundled jre"
  else
    JAVA="$OPENSEARCH_HOME/jdk/bin/java"
    JAVA_TYPE="bundled jdk"
  fi
fi

if [ ! -x "$JAVA" ]; then
    echo "could not find java in $JAVA_TYPE at $JAVA" >&2
    exit 1
fi

"$JAVA" -Dorg.apache.logging.log4j.simplelog.StatusLogger.level=OFF -cp "$DIR/../*:$DIR/../../../lib/*:$DIR/../deps/*" org.opensearch.security.tools.democonfig.Installer "$DIR" "$@" 2>/dev/null
