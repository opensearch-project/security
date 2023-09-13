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

set -e
BASE_DIR="$DIR/../../.."
if [ -d "$BASE_DIR" ]; then
	CUR="$(pwd)"
	cd "$BASE_DIR"
	BASE_DIR="$(pwd)"
	cd "$CUR"
	echo "Basedir: $BASE_DIR"
else
    echo "DEBUG: basedir does not exist"
fi

OPENSEARCH_CONF_FILE="$BASE_DIR/config/opensearch.yml"
INTERNAL_USERS_FILE="$BASE_DIR/config/internal_users.yml"

ADMIN_PASSWORD=$(grep -op 'plugins.security.bootstrap.admin.password:\s*\K.+' "$OPENSEARCH_CONF_FILE" | awk '{print $1}')

if [ -z "$ADMIN_PASSWORD" ]; then
  echo "Admin password not found in $OPENSEARCH_CONF_FILE and ENV_ADMIN_PASSWORD is not set."
  exit 1
fi

salt=$(openssl rand -hex 8)

# Generate the hash using OpenBSD-style Blowfish-based bcrypt
HASHED_ADMIN_PASSWORD=$(openssl passwd -bcrypt -salt $salt "$ADMIN_PASSWORD")

# Clear the clearTextPassword variable
unset ADMIN_PASSWORD

ADMIN_HASH_LINE=$(grep -n 'admin:' "$INTERNAL_USERS_FILE" | cut -f1 -d:)

sed -i "${ADMIN_HASH_LINE}s/.*/  hash: \"$HASHED_ADMIN_PASSWORD\"/" "$INTERNAL_USERS_FILE"
