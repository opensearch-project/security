#!/bin/bash
#install_demo_configuration.sh [-y]

echo "**************************************************************************"
echo "** This tool will be deprecated in the next major release of OpenSearch **"
echo "** https://github.com/opensearch-project/security/issues/1755           **"
echo "**************************************************************************"

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

read -r -d '' ADMIN_CERT << EOM
-----BEGIN CERTIFICATE-----
MIIEmDCCA4CgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iYwDQYJKoZIhvcNAQEL
BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt
cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl
IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v
dCBDQTAeFw0yMzA4MjkyMDA2MzdaFw0zMzA4MjYyMDA2MzdaME0xCzAJBgNVBAYT
AmRlMQ0wCwYDVQQHDAR0ZXN0MQ8wDQYDVQQKDAZjbGllbnQxDzANBgNVBAsMBmNs
aWVudDENMAsGA1UEAwwEa2lyazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAJVcOAQlCiuB9emCljROAXnlsPbG7PE3kNz2sN+BbGuw686Wgyl3uToVHvVs
paMmLUqm1KYz9wMSWTIBZgpJ9hYaIbGxD4RBb7qTAJ8Q4ddCV2f7T4lxao/6ixI+
O0l/BG9E3mRGo/r0w+jtTQ3aR2p6eoxaOYbVyEMYtFI4QZTkcgGIPGxm05y8xonx
vV5pbSW9L7qAVDzQC8EYGQMMI4ccu0NcHKWtmTYJA/wDPE2JwhngHwbcIbc4cDz6
cG0S3FmgiKGuuSqUy35v/k3y7zMHQSdx7DSR2tzhH/bBL/9qGvpT71KKrxPtaxS0
bAqPcEkKWDo7IMlGGW7LaAWfGg8CAwEAAaOCASswggEnMAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgXgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMIHPBgNVHSME
gccwgcSAFBeH36Ba62YSp9XQ+LoSRTy3KwCcoYGVpIGSMIGPMRMwEQYKCZImiZPy
LGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQRXhh
bXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENB
MSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0GCFHfkrz782p+T9k0G
xGeM4+BrehWKMB0GA1UdDgQWBBSjMS8tgguX/V7KSGLoGg7K6XMzIDANBgkqhkiG
9w0BAQsFAAOCAQEANMwD1JYlwAh82yG1gU3WSdh/tb6gqaSzZK7R6I0L7slaXN9m
y2ErUljpTyaHrdiBFmPhU/2Kj2r+fIUXtXdDXzizx/JdmueT0nG9hOixLqzfoC9p
fAhZxM62RgtyZoaczQN82k1/geMSwRpEndFe3OH7arkS/HSbIFxQhAIy229eWe5d
1bUzP59iu7f3r567I4ob8Vy7PP+Ov35p7Vv4oDHHwgsdRzX6pvL6mmwVrQ3BfVec
h9Dqprr+ukYmjho76g6k5cQuRaB6MxqldzUg+2E7IHQP8MCF+co51uZq2nl33mtp
RGr6JbdHXc96zsLTL3saJQ8AWEfu1gbTVrwyRA==
-----END CERTIFICATE-----
EOM

read -r -d '' ADMIN_CERT_KEY << EOM
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVXDgEJQorgfXp
gpY0TgF55bD2xuzxN5Dc9rDfgWxrsOvOloMpd7k6FR71bKWjJi1KptSmM/cDElky
AWYKSfYWGiGxsQ+EQW+6kwCfEOHXQldn+0+JcWqP+osSPjtJfwRvRN5kRqP69MPo
7U0N2kdqenqMWjmG1chDGLRSOEGU5HIBiDxsZtOcvMaJ8b1eaW0lvS+6gFQ80AvB
GBkDDCOHHLtDXBylrZk2CQP8AzxNicIZ4B8G3CG3OHA8+nBtEtxZoIihrrkqlMt+
b/5N8u8zB0Encew0kdrc4R/2wS//ahr6U+9Siq8T7WsUtGwKj3BJClg6OyDJRhlu
y2gFnxoPAgMBAAECggEAP5TOycDkx+megAWVoHV2fmgvgZXkBrlzQwUG/VZQi7V4
ZGzBMBVltdqI38wc5MtbK3TCgHANnnKgor9iq02Z4wXDwytPIiti/ycV9CDRKvv0
TnD2hllQFjN/IUh5n4thHWbRTxmdM7cfcNgX3aZGkYbLBVVhOMtn4VwyYu/Mxy8j
xClZT2xKOHkxqwmWPmdDTbAeZIbSv7RkIGfrKuQyUGUaWhrPslvYzFkYZ0umaDgQ
OAthZew5Bz3OfUGOMPLH61SVPuJZh9zN1hTWOvT65WFWfsPd2yStI+WD/5PU1Doo
1RyeHJO7s3ug8JPbtNJmaJwHe9nXBb/HXFdqb976yQKBgQDNYhpu+MYSYupaYqjs
9YFmHQNKpNZqgZ4ceRFZ6cMJoqpI5dpEMqToFH7tpor72Lturct2U9nc2WR0HeEs
/6tiptyMPTFEiMFb1opQlXF2ae7LeJllntDGN0Q6vxKnQV+7VMcXA0Y8F7tvGDy3
qJu5lfvB1mNM2I6y/eMxjBuQhwKBgQC6K41DXMFro0UnoO879pOQYMydCErJRmjG
/tZSy3Wj4KA/QJsDSViwGfvdPuHZRaG9WtxdL6kn0w1exM9Rb0bBKl36lvi7o7xv
M+Lw9eyXMkww8/F5d7YYH77gIhGo+RITkKI3+5BxeBaUnrGvmHrpmpgRXWmINqr0
0jsnN3u0OQKBgCf45vIgItSjQb8zonLz2SpZjTFy4XQ7I92gxnq8X0Q5z3B+o7tQ
K/4rNwTju/sGFHyXAJlX+nfcK4vZ4OBUJjP+C8CTjEotX4yTNbo3S6zjMyGQqDI5
9aIOUY4pb+TzeUFJX7If5gR+DfGyQubvvtcg1K3GHu9u2l8FwLj87sRzAoGAflQF
RHuRiG+/AngTPnZAhc0Zq0kwLkpH2Rid6IrFZhGLy8AUL/O6aa0IGoaMDLpSWUJp
nBY2S57MSM11/MVslrEgGmYNnI4r1K25xlaqV6K6ztEJv6n69327MS4NG8L/gCU5
3pEm38hkUi8pVYU7in7rx4TCkrq94OkzWJYurAkCgYATQCL/rJLQAlJIGulp8s6h
mQGwy8vIqMjAdHGLrCS35sVYBXG13knS52LJHvbVee39AbD5/LlWvjJGlQMzCLrw
F7oILW5kXxhb8S73GWcuMbuQMFVHFONbZAZgn+C9FW4l7XyRdkrbR1MRZ2km8YMs
/AHmo368d4PSNRMMzLHw8Q==
-----END PRIVATE KEY-----
EOM

read -r -d '' NODE_CERT << EOM
-----BEGIN CERTIFICATE-----
MIIEPDCCAySgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iIwDQYJKoZIhvcNAQEL
BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt
cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl
IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v
dCBDQTAeFw0yMzA4MjkwNDIzMTJaFw0zMzA4MjYwNDIzMTJaMFcxCzAJBgNVBAYT
AmRlMQ0wCwYDVQQHDAR0ZXN0MQ0wCwYDVQQKDARub2RlMQ0wCwYDVQQLDARub2Rl
MRswGQYDVQQDDBJub2RlLTAuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCm93kXteDQHMAvbUPNPW5pyRHKDD42XGWSgq0k1D29C/Ud
yL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0
HGkn47XVu3EwbfrTENg3jFu+Oem6a/501SzITzJWtS0cn2dIFOBimTVpT/4Zv5qr
XA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8n
dibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b6l+KLo3IKpfTbAIJXIO+M67FLtWKtttD
ao94B069skzKk6FPgW/OZh6PRCD0oxOavV+ld2SjAgMBAAGjgcYwgcMwRwYDVR0R
BEAwPogFKgMEBQWCEm5vZGUtMC5leGFtcGxlLmNvbYIJbG9jYWxob3N0hxAAAAAA
AAAAAAAAAAAAAAABhwR/AAABMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU0/qDQaY10jIo
wCjLUpz/HfQXyt8wHwYDVR0jBBgwFoAUF4ffoFrrZhKn1dD4uhJFPLcrAJwwDQYJ
KoZIhvcNAQELBQADggEBAD2hkndVih6TWxoe/oOW0i2Bq7ScNO/n7/yHWL04HJmR
MaHv/Xjc8zLFLgHuHaRvC02ikWIJyQf5xJt0Oqu2GVbqXH9PBGKuEP2kCsRRyU27
zTclAzfQhqmKBTYQ/3lJ3GhRQvXIdYTe+t4aq78TCawp1nSN+vdH/1geG6QjMn5N
1FU8tovDd4x8Ib/0dv8RJx+n9gytI8n/giIaDCEbfLLpe4EkV5e5UNpOnRgJjjuy
vtZutc81TQnzBtkS9XuulovDE0qI+jQrKkKu8xgGLhgH0zxnPkKtUg2I3Aq6zl1L
zYkEOUF8Y25J6WeY88Yfnc0iigI+Pnz5NK8R9GL7TYo=
-----END CERTIFICATE-----
EOM

read -r -d '' NODE_KEY << EOM
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm93kXteDQHMAv
bUPNPW5pyRHKDD42XGWSgq0k1D29C/UdyL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0
o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0HGkn47XVu3EwbfrTENg3jFu+Oem6a/50
1SzITzJWtS0cn2dIFOBimTVpT/4Zv5qrXA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1
MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8ndibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b
6l+KLo3IKpfTbAIJXIO+M67FLtWKtttDao94B069skzKk6FPgW/OZh6PRCD0oxOa
vV+ld2SjAgMBAAECggEAQK1+uAOZeaSZggW2jQut+MaN4JHLi61RH2cFgU3COLgo
FIiNjFn8f2KKU3gpkt1It8PjlmprpYut4wHI7r6UQfuv7ZrmncRiPWHm9PB82+ZQ
5MXYqj4YUxoQJ62Cyz4sM6BobZDrjG6HHGTzuwiKvHHkbsEE9jQ4E5m7yfbVvM0O
zvwrSOM1tkZihKSTpR0j2+taji914tjBssbn12TMZQL5ItGnhR3luY8mEwT9MNkZ
xg0VcREoAH+pu9FE0vPUgLVzhJ3be7qZTTSRqv08bmW+y1plu80GbppePcgYhEow
dlW4l6XPJaHVSn1lSFHE6QAx6sqiAnBz0NoTPIaLyQKBgQDZqDOlhCRciMRicSXn
7yid9rhEmdMkySJHTVFOidFWwlBcp0fGxxn8UNSBcXdSy7GLlUtH41W9PWl8tp9U
hQiiXORxOJ7ZcB80uNKXF01hpPj2DpFPWyHFxpDkWiTAYpZl68rOlYujxZUjJIej
VvcykBC2BlEOG9uZv2kxcqLyJwKBgQDEYULTxaTuLIa17wU3nAhaainKB3vHxw9B
Ksy5p3ND43UNEKkQm7K/WENx0q47TA1mKD9i+BhaLod98mu0YZ+BCUNgWKcBHK8c
uXpauvM/pLhFLXZ2jvEJVpFY3J79FSRK8bwE9RgKfVKMMgEk4zOyZowS8WScOqiy
hnQn1vKTJQKBgElhYuAnl9a2qXcC7KOwRsJS3rcKIVxijzL4xzOyVShp5IwIPbOv
hnxBiBOH/JGmaNpFYBcBdvORE9JfA4KMQ2fx53agfzWRjoPI1/7mdUk5RFI4gRb/
A3jZRBoopgFSe6ArCbnyQxzYzToG48/Wzwp19ZxYrtUR4UyJct6f5n27AoGBAJDh
KIpQQDOvCdtjcbfrF4aM2DPCfaGPzENJriwxy6oEPzDaX8Bu/dqI5Ykt43i/zQrX
GpyLaHvv4+oZVTiI5UIvcVO9U8hQPyiz9f7F+fu0LHZs6f7hyhYXlbe3XFxeop3f
5dTKdWgXuTTRF2L9dABkA2deS9mutRKwezWBMQk5AoGBALPtX0FrT1zIosibmlud
tu49A/0KZu4PBjrFMYTSEWGNJez3Fb2VsJwylVl6HivwbP61FhlYfyksCzQQFU71
+x7Nmybp7PmpEBECr3deoZKQ/acNHn0iwb0It+YqV5+TquQebqgwK6WCLsMuiYKT
bg/ch9Rhxbq22yrVgWHh6epp
-----END PRIVATE KEY-----
EOM

read -r -d '' ROOT_CA << EOM
-----BEGIN CERTIFICATE-----
MIIExjCCA66gAwIBAgIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcNAQEL
BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt
cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl
IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v
dCBDQTAeFw0yMzA4MjkwNDIwMDNaFw0yMzA5MjgwNDIwMDNaMIGPMRMwEQYKCZIm
iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ
RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290
IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEPyN7J9VGPyJcQmCBl5TGwfSzvVdWwoQU
j9aEsdfFJ6pBCDQSsj8Lv4RqL0dZra7h7SpZLLX/YZcnjikrYC+rP5OwsI9xEE/4
U98CsTBPhIMgqFK6SzNE5494BsAk4cL72dOOc8tX19oDS/PvBULbNkthQ0aAF1dg
vbrHvu7hq7LisB5ZRGHVE1k/AbCs2PaaKkn2jCw/b+U0Ml9qPuuEgz2mAqJDGYoA
WSR4YXrOcrmPuRqbws464YZbJW898/0Pn/U300ed+4YHiNYLLJp51AMkR4YEw969
VRPbWIvLrd0PQBooC/eLrL6rvud/GpYhdQEUx8qcNCKd4bz3OaQ5AgMBAAGjggEW
MIIBEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU
F4ffoFrrZhKn1dD4uhJFPLcrAJwwgc8GA1UdIwSBxzCBxIAUF4ffoFrrZhKn1dD4
uhJFPLcrAJyhgZWkgZIwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYD
VQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUg
Q29tIEluYy4gUm9vdCBDQYIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcN
AQELBQADggEBAIopqco/k9RSjouTeKP4z0EVUxdD4qnNh1GLSRqyAVe0aChyKF5f
qt1Bd1XCY8D16RgekkKGHDpJhGCpel+vtIoXPBxUaGQNYxmJCf5OzLMODlcrZk5i
jHIcv/FMeK02NBcz/WQ3mbWHVwXLhmwqa2zBsF4FmPCJAbFLchLhkAv1HJifHbnD
jQzlKyl5jxam/wtjWxSm0iyso0z2TgyzY+MESqjEqB1hZkCFzD1xtUOCxbXgtKae
dgfHVFuovr3fNLV3GvQk0s9okDwDUcqV7DSH61e5bUMfE84o3of8YA7+HUoPV5Du
8sTOKRf7ncGXdDRA8aofW268pTCuIu3+g/Y=
-----END CERTIFICATE-----
EOM

set -e

echo "$ADMIN_CERT" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/kirk.pem" > /dev/null
echo "$NODE_CERT" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/esnode.pem" > /dev/null
echo "$ROOT_CA" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/root-ca.pem" > /dev/null
echo "$NODE_KEY" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/esnode-key.pem" > /dev/null
echo "$ADMIN_CERT_KEY" | $SUDO_CMD tee "$OPENSEARCH_CONF_DIR/kirk-key.pem" > /dev/null

chmod 0600 "$OPENSEARCH_CONF_DIR/kirk.pem"
chmod 0600 "$OPENSEARCH_CONF_DIR/esnode.pem"
chmod 0600 "$OPENSEARCH_CONF_DIR/root-ca.pem"
chmod 0600 "$OPENSEARCH_CONF_DIR/esnode-key.pem"
chmod 0600 "$OPENSEARCH_CONF_DIR/kirk-key.pem"

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
echo 'plugins.security.system_indices.indices: [".plugins-ml-config", ".plugins-ml-connector", ".plugins-ml-model-group", ".plugins-ml-model", ".plugins-ml-task", ".plugins-ml-conversation-meta", ".plugins-ml-conversation-interactions", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".ql-datasources", ".opendistro-asynchronous-search-response*", ".replication-metadata-store", ".opensearch-knn-models", ".geospatial-ip2geo-data*"]' | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null

## Read the admin password from the file or use the initialAdminPassword if set
ADMIN_PASSWORD_FILE="$OPENSEARCH_CONF_DIR/initialAdminPassword.txt"
INTERNAL_USERS_FILE="$OPENSEARCH_CONF_DIR/opensearch-security/internal_users.yml"

if [[ -n "$initialAdminPassword" ]]; then
  ADMIN_PASSWORD="$initialAdminPassword"
elif [[ -f "$ADMIN_PASSWORD_FILE" && -s "$ADMIN_PASSWORD_FILE" ]]; then
  ADMIN_PASSWORD=$(head -n 1 "$ADMIN_PASSWORD_FILE")
else
  echo "Unable to find the admin password for the cluster. Please run 'export initialAdminPassword=<your_password>' or create a file $ADMIN_PASSWORD_FILE with a single line that contains the password."
  exit 1
fi

echo "   ***************************************************"
echo "   ***   ADMIN PASSWORD SET TO: $ADMIN_PASSWORD    ***"
echo "   ***************************************************"

$SUDO_CMD chmod +x "$OPENSEARCH_PLUGINS_DIR/opensearch-security/tools/hash.sh"

# Use the Hasher script to hash the admin password
HASHED_ADMIN_PASSWORD=$($OPENSEARCH_PLUGINS_DIR/opensearch-security/tools/hash.sh -p "$ADMIN_PASSWORD" | tail -n 1)

if [ $? -ne 0 ]; then
  echo "Hash the admin password failure, see console for details"
  exit 1
fi

# Find the line number containing 'admin:' in the internal_users.yml file
ADMIN_HASH_LINE=$(grep -n 'admin:' "$INTERNAL_USERS_FILE" | cut -f1 -d:)

awk -v hashed_admin_password="$HASHED_ADMIN_PASSWORD" '
  /^ *hash: *"\$2a\$12\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR\/YFJcgHp0UGns5JDymv..TOG"/ {
    sub(/"\$2a\$12\$VcCDgh2NDk07JGN0rjGbM.Ad41qVR\/YFJcgHp0UGns5JDymv..TOG"/, "\"" hashed_admin_password "\"");
  }
  { print }
' "$INTERNAL_USERS_FILE" > temp_file && mv temp_file "$INTERNAL_USERS_FILE"

#network.host
if $SUDO_CMD grep --quiet -i "^network.host" "$OPENSEARCH_CONF_FILE"; then
	: #already present
else
	if [ "$cluster_mode" == 1 ]; then
        echo "network.host: 0.0.0.0" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
        echo "node.name: smoketestnode" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
        echo "cluster.initial_cluster_manager_nodes: smoketestnode" | $SUDO_CMD tee -a "$OPENSEARCH_CONF_FILE" > /dev/null
    fi
fi

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
echo $SUDO_CMD \""$OPENSEARCH_PLUGINS_DIR/opensearch-security/tools/securityadmin.sh"\" -cd \""$OPENSEARCH_CONF_DIR/opensearch-security"\" -icl -key \""$OPENSEARCH_CONF_DIR/kirk-key.pem"\" -cert \""$OPENSEARCH_CONF_DIR/kirk.pem"\" -cacert \""$OPENSEARCH_CONF_DIR/root-ca.pem"\" -nhnv | $SUDO_CMD tee -a securityadmin_demo.sh > /dev/null
$SUDO_CMD chmod +x securityadmin_demo.sh

if [ "$initsecurity" == 0 ]; then
	echo "### After the whole cluster is up execute: "
	$SUDO_CMD cat securityadmin_demo.sh | tail -1
	echo "### or run ./securityadmin_demo.sh"
    echo "### After that you can also use the Security Plugin ConfigurationGUI"
else
    echo "### OpenSearch Security will be automatically initialized."
    echo "### If you like to change the runtime configuration "
    echo "### change the files in ../../../config/opensearch-security and execute: "
	$SUDO_CMD cat securityadmin_demo.sh | tail -1
	echo "### or run ./securityadmin_demo.sh"
	echo "### To use the Security Plugin ConfigurationGUI"
fi

echo "### To access your secured cluster open https://<hostname>:<HTTP port> and log in with admin/admin."
echo "### (Ignore the SSL certificate warning because we installed self-signed demo certificates)"
