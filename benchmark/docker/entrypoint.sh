#!/bin/bash

export OPENSEARCH_HOME=/usr/share/opensearch

chmod +x  "$OPENSEARCH_HOME"/plugins/opensearch-security/tools/install_demo_configuration.sh
bash "$OPENSEARCH_HOME"/plugins/opensearch-security/tools/install_demo_configuration.sh -y -i -s || exit 1

function runOpensearch {
    umask 0002

    if [[ "$(id -u)" == "0" ]]; then
        echo "OpenSearch cannot run as root. Please start your container as another user."
        exit 1
    fi

    opensearch_opts=()
    while IFS='=' read -r envvar_key envvar_value
    do
        if [[ "$envvar_key" =~ ^[a-z0-9_]+\.[a-z0-9_]+ || "$envvar_key" == "processors" ]]; then
            if [[ ! -z $envvar_value ]]; then
            opensearch_opt="-E${envvar_key}=${envvar_value}"
            opensearch_opts+=("${opensearch_opt}")
            fi
        fi
    done < <(env)

    "$@" "${opensearch_opts[@]}"
}

if [ $# -eq 0 ] || [ "${1:0:1}" = '-' ]; then
    set -- opensearch "$@"
fi

if [ "$1" = "opensearch" ]; then
    runOpensearch "$@"
else
    exec "$@"
fi