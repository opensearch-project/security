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

echo "OpenSearch Security Demo Installer"
echo " ** Warning: Do not use on production or public reachable systems **"

OPTIND=1
assumeyes=0
initsecurity=0
cluster_mode=0
skip_updates=-1

function show_help() {
    echo "install_demo_configuration.sh [-y] [-i] [-c]"
    echo "  -h show help"
    echo "  -y confirm all installation dialogues automatically"
    echo "  -i initialize Security plugin with default configuration (default is to ask if -y is not given)"
    echo "  -c enable cluster mode by binding to all network interfaces (default is to ask if -y is not given)"
    echo "  -s skip updates if config is already applied to opensearch.yml"
}

while getopts "h?yics" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    y)  assumeyes=1
        ;;
    i)  initsecurity=1
        ;;
    c)  cluster_mode=1
        ;;
    s)  skip_updates=0
    esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift

if [ "$assumeyes" == 0 ]; then
	read -r -p "Install demo certificates? [y/N] " response
	case "$response" in
	    [yY][eE][sS]|[yY]) 
	        ;;
	    *)
	        exit 0
	        ;;
	esac
fi

if [ "$initsecurity" == 0 ] && [ "$assumeyes" == 0 ]; then
	read -r -p "Initialize Security Modules? [y/N] " response
	case "$response" in
	    [yY][eE][sS]|[yY]) 
	        initsecurity=1
	        ;;
	    *)
	        initsecurity=0
	        ;;
	esac
fi

if [ "$cluster_mode" == 0 ] && [ "$assumeyes" == 0 ]; then
    echo "Cluster mode requires maybe additional setup of:"
    echo "  - Virtual memory (vm.max_map_count)"
    echo ""
	read -r -p "Enable cluster mode? [y/N] " response
	case "$response" in
	    [yY][eE][sS]|[yY]) 
	        cluster_mode=1
	        ;;
	    *)
	        cluster_mode=0
	        ;;
	esac
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
OPENSEARCH_BIN_DIR="$BASE_DIR/bin"
OPENSEARCH_PLUGINS_DIR="$BASE_DIR/plugins"
OPENSEARCH_MODULES_DIR="$BASE_DIR/modules"
OPENSEARCH_LIB_PATH="$BASE_DIR/lib"
SUDO_CMD=""
OPENSEARCH_INSTALL_TYPE=".tar.gz"

#Check if its a rpm/deb install
if [ "/usr/share/opensearch" -ef "$BASE_DIR" ]; then
    OPENSEARCH_CONF_FILE="/usr/share/opensearch/config/opensearch.yml"

    if [ ! -f "$OPENSEARCH_CONF_FILE" ]; then
        OPENSEARCH_CONF_FILE="/etc/opensearch/opensearch.yml"
    fi

    if [ -x "$(command -v sudo)" ]; then
        SUDO_CMD="sudo"
        echo "This script maybe require your root password for 'sudo' privileges"
    fi

    OPENSEARCH_INSTALL_TYPE="rpm/deb"
fi

if [ $SUDO_CMD ]; then
    if ! [ -x "$(command -v $SUDO_CMD)" ]; then
        echo "Unable to locate 'sudo' command. Quit."
        exit 1
    fi
fi

if $SUDO_CMD test -f "$OPENSEARCH_CONF_FILE"; then
    :
else
    echo "Unable to determine OpenSearch config directory. Quit."
    exit -1
fi

if [ ! -d "$OPENSEARCH_BIN_DIR" ]; then
	echo "Unable to determine OpenSearch bin directory. Quit."
	exit -1
fi

if [ ! -d "$OPENSEARCH_PLUGINS_DIR" ]; then
	echo "Unable to determine OpenSearch plugins directory. Quit."
	exit -1
fi

if [ ! -d "$OPENSEARCH_MODULES_DIR" ]; then
	echo "Unable to determine OpenSearch modules directory. Quit."
	#exit -1
fi

if [ ! -d "$OPENSEARCH_LIB_PATH" ]; then
	echo "Unable to determine OpenSearch lib directory. Quit."
	exit -1
fi

OPENSEARCH_CONF_DIR=$(dirname "${OPENSEARCH_CONF_FILE}")
OPENSEARCH_CONF_DIR=`cd "$OPENSEARCH_CONF_DIR" ; pwd`

if [ ! -d "$OPENSEARCH_PLUGINS_DIR/opensearch-security" ]; then
  echo "OpenSearch Security plugin not installed. Quit."
  exit -1
fi

OPENSEARCH_VERSION=("$OPENSEARCH_LIB_PATH/opensearch-*.jar")
OPENSEARCH_VERSION=$(echo $OPENSEARCH_VERSION | sed 's/.*opensearch-\(.*\)\.jar/\1/')

SECURITY_VERSION=("$OPENSEARCH_PLUGINS_DIR/opensearch-security/opensearch-security-*.jar")
SECURITY_VERSION=$(echo $SECURITY_VERSION | sed 's/.*opensearch-security-\(.*\)\.jar/\1/')

OS=$(sb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1 || uname -om)
echo "OpenSearch install type: $OPENSEARCH_INSTALL_TYPE on $OS"
echo "OpenSearch config dir: $OPENSEARCH_CONF_DIR"
echo "OpenSearch config file: $OPENSEARCH_CONF_FILE"
echo "OpenSearch bin dir: $OPENSEARCH_BIN_DIR"
echo "OpenSearch plugins dir: $OPENSEARCH_PLUGINS_DIR"
echo "OpenSearch lib dir: $OPENSEARCH_LIB_PATH"
echo "Detected OpenSearch Version: $OPENSEARCH_VERSION"
echo "Detected OpenSearch Security Version: $SECURITY_VERSION"

if $SUDO_CMD grep --quiet -i plugins.security "$OPENSEARCH_CONF_FILE"; then
  echo "$OPENSEARCH_CONF_FILE seems to be already configured for Security. Quit."
  exit $skip_updates
fi

set +e

set -e

#echo "$ADMIN_CERT" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/kirk.pem" > /dev/null
#echo "$NODE_CERT" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/esnode.pem" > /dev/null
#echo "$ROOT_CA" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/root-ca.pem" > /dev/null
#echo "$NODE_KEY" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/esnode-key.pem" > /dev/null
#echo "$ADMIN_CERT_KEY" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/kirk-key.pem" > /dev/null
echo "Hi"
cd "$OPENSEARCH_CONF_DIR"
openssl genrsa -out root-ca-key.pem 2048
openssl req -new -x509 -sha256 -key root-ca-key.pem -out root-ca.pem -days 730
# Admin cert
openssl genrsa -out kirk-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in kirk-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out kirk-key.pem
openssl req -new -key kirk-key.pem -out kirk.csr
openssl x509 -req -in kirk.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out kirk.pem -days 730
# Node cert
openssl genrsa -out esnode-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in esnode-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out esnode-key.pem
openssl req -new -key esnode-key.pem -out esnode.csr
openssl x509 -req -in esnode.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out esnode.pem -days 730
# Cleanup
rm kirk-key-temp.pem
rm kirk.csr
rm esnode-key-temp.pem
rm esnode.csr

cd ..
echo "" | $SUDO_CMD tee -a  "$OPENSEARCH_CONF_FILE"
echo "######## Start OpenSearch Security Demo Configuration ########" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "# WARNING: revise all the lines below before you go into production" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.transport.pemcert_filepath: esnode.pem" | $SUDO_CMD tee -a  "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem" | $SUDO_CMD tee -a  "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.transport.enforce_hostname_verification: false" | $SUDO_CMD tee -a  "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.http.enabled: true" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.http.pemcert_filepath: esnode.pem" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.http.pemkey_filepath: esnode-key.pem" | $SUDO_CMD tee -a  "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.allow_unsafe_democertificates: true" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
if [ "$initsecurity" == 1 ]; then
    echo "plugins.security.allow_default_init_securityindex: true" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
fi
echo "plugins.security.authcz.admin_dn:" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "  - CN=kirk,OU=client,O=client,L=test, C=de" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.audit.type: internal_opensearch" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.enable_snapshot_restore_privilege: true" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo "plugins.security.check_snapshot_restore_write_privileges: true" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo 'plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]' | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo 'plugins.security.system_indices.enabled: true' | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
echo 'plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]' | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null

#network.host
if $SUDO_CMD grep --quiet -i "^network.host" "$OPENSEARCH_CONF_FILE"; then
	: #already present
else
	if [ "$cluster_mode" == 1 ]; then
        echo "network.host: 0.0.0.0" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
        echo "node.name: smoketestnode" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
        echo "cluster.initial_master_nodes: smoketestnode" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
    fi
fi

#discovery.zen.minimum_master_nodes
#if $SUDO_CMD grep --quiet -i "^discovery.zen.minimum_master_nodes" "$OPENSEARCH_CONF_FILE"; then
#	: #already present
#else
#    echo "discovery.zen.minimum_master_nodes: 1" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
#fi

#node.max_local_storage_nodes
if $SUDO_CMD grep --quiet -i "^node.max_local_storage_nodes" "$OPENSEARCH_CONF_FILE"; then
	: #already present
else
    echo 'node.max_local_storage_nodes: 3' | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
fi



echo "######## End OpenSearch Security Demo Configuration ########" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null

$SUDO_CMD chmod +x "$OPENSEARCH_PLUGINS_DIR/opensearch-security/tools/securityadmin.sh"

OPENSEARCH_PLUGINS_DIR=`cd "$OPENSEARCH_PLUGINS_DIR" ; pwd`

echo "### Success"
echo "### Execute this script now on all your nodes and then start all nodes"
#Generate securityadmin_demo.sh
echo "#!/bin/bash" | $SUDO_CMD tee securityadmin_demo.sh > /dev/null 
echo $SUDO_CMD \""$OPENSEARCH_PLUGINS_DIR/opensearch-security/tools/securityadmin.sh"\" -cd \""$OPENSEARCH_PLUGINS_DIR/opensearch-security/securityconfig"\" -icl -key \""$OPENSEARCH_CONF_DIR/kirk-key.pem"\" -cert \""$OPENSEARCH_CONF_DIR/kirk.pem"\" -cacert \""$OPENSEARCH_CONF_DIR/root-ca.pem"\" -nhnv | $SUDO_CMD tee -a securityadmin_demo.sh > /dev/null
$SUDO_CMD chmod +x securityadmin_demo.sh

if [ "$initsecurity" == 0 ]; then
	echo "### After the whole cluster is up execute: "
	$SUDO_CMD cat securityadmin_demo.sh | tail -1
	echo "### or run ./securityadmin_demo.sh"
    echo "### After that you can also use the Security Plugin ConfigurationGUI"
else
    echo "### OpenSearch Security will be automatically initialized."
    echo "### If you like to change the runtime configuration "
    echo "### change the files in ../securityconfig and execute: "
	$SUDO_CMD cat securityadmin_demo.sh | tail -1
	echo "### or run ./securityadmin_demo.sh"
	echo "### To use the Security Plugin ConfigurationGUI"
fi

echo "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/admin."
echo "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)"
