#!/bin/bash

set -e

function usage() {
    echo ""
    echo "This script is used to run integration tests for plugin installed on a remote OpenSearch/Dashboards cluster."
    echo "--------------------------------------------------------------------------"
    echo "Usage: $0 [args]"
    echo ""
    echo "Required arguments:"
    echo "None"
    echo ""
    echo "Optional arguments:"
    echo -e "-b BIND_ADDRESS\t, defaults to localhost | 127.0.0.1, can be changed to any IP or domain name for the cluster location."
    echo -e "-p BIND_PORT\t, defaults to 9200, can be changed to any port for the cluster location."
    echo -e "-s SECURITY_ENABLED\t(true | false), defaults to true. Specify the OpenSearch/Dashboards have security enabled or not."
    echo -e "-c CREDENTIAL\t(usename:password), no defaults, effective when SECURITY_ENABLED=true."
    echo -e "-h\tPrint this message."
    echo -e "-v OPENSEARCH_VERSION\t, no defaults"
    echo -e "-n SNAPSHOT\t, defaults to false"
    echo -e "-m CLUSTER_NAME\t, defaults to docker-cluster"
    echo -e "-u COMMON_UTILS_VERSION\t, defaults to 3.0.0.0-SNAPSHOT"
    echo "--------------------------------------------------------------------------"
}

while getopts ":h:b:p:s:c:v:n:t:m:u:" arg; do
    case $arg in
        h)
            usage
            exit 1
            ;;
        b)
            BIND_ADDRESS=$OPTARG
            ;;
        p)
            BIND_PORT=$OPTARG
            ;;
        t)
            TRANSPORT_PORT=$OPTARG
            ;;
        s)
            SECURITY_ENABLED=$OPTARG
            ;;
        c)
            CREDENTIAL=$OPTARG
            ;;
        m)
            CLUSTER_NAME=$OPTARG
            ;;
        v)
            # Do nothing as we're not consuming this param.
            ;;
        n)
            # Do nothing as we're not consuming this param.
            ;;
        u)
            COMMON_UTILS_VERSION=$OPTARG
            ;;
        :)
            echo "-${OPTARG} requires an argument"
            usage
            exit 1
            ;;
        ?)
            echo "Invalid option: -${OPTARG}"
            exit 1
            ;;
    esac
done


if [ -z "$BIND_ADDRESS" ]
then
  BIND_ADDRESS="localhost"
fi

if [ -z "$BIND_PORT" ]
then
  BIND_PORT="9200"
fi

if [ -z "$SECURITY_ENABLED" ]
then
  SECURITY_ENABLED="true"
fi

if [ -z "$CREDENTIAL" ]
then
  CREDENTIAL="admin:admin"
fi

if [ -z "$CREDENTIAL" ]
then
  CREDENTIAL="admin:admin"
fi

if [ -z "$CLUSTER_NAME" ]
then
  CLUSTER_NAME="docker-cluster"
fi
if [ -z "$COMMON_UTILS_VERSION" ]
then
  COMMON_UTILS_VERSION="3.0.0.0-SNAPSHOT"
fi

USERNAME=`echo $CREDENTIAL | awk -F ':' '{print $1}'`
PASSWORD=`echo $CREDENTIAL | awk -F ':' '{print $2}'`

./gradlew integTestRemote -Dtests.rest.cluster="$BIND_ADDRESS:$BIND_PORT" -Dtests.cluster="$BIND_ADDRESS:$BIND_PORT" -Dsecurity_enabled=$SECURITY_ENABLED -Dtests.clustername=$CLUSTER_NAME -Dhttps=true -Duser=$USERNAME -Dpassword=$PASSWORD -Dcommon_utils.version=$COMMON_UTILS_VERSION
