#!/bin/bash
#install_demo_configuration.sh [-y]
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Search Guard 6 Demo Installer"
echo " ** Warning: Do not use on production or public reachable systems **"

OPTIND=1
assumeyes=0
initsg=0

function show_help() {
    echo "install_demo_configuration.sh [-y] [-i]"
    echo "  -h show help"
    echo "  -y do not ask no confirmation for installation"
    echo "  -i initialize Search Guard with default configuration (default is to ask)"
}

while getopts "h?yi" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    y)  assumeyes=1
        ;;
    i)  initsg=1
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

if [ "$initsg" == 0 ]; then
	read -r -p "Initialize Search Guard? [y/N] " response
	case "$response" in
	    [yY][eE][sS]|[yY]) 
	        initsg=1
	        ;;
	    *)
	        initsg=0
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
ES_CONF_FILE="$BASE_DIR/config/elasticsearch.yml"
ES_BIN_DIR="$BASE_DIR/bin"
ES_PLUGINS_DIR="$BASE_DIR/plugins"
ES_LIB_PATH="$BASE_DIR/lib"
SUDO_CMD=""
ES_INSTALL_TYPE=".tar.gz"

#Check if its a rpm/deb install
if [ -f /usr/share/elasticsearch/bin/elasticsearch ]; then
    ES_CONF_FILE="/usr/share/elasticsearch/config/elasticsearch.yml"

    if [ ! -f "$ES_CONF_FILE" ]; then
        ES_CONF_FILE="/etc/elasticsearch/elasticsearch.yml"
    fi

    ES_BIN_DIR="/usr/share/elasticsearch/bin"
    ES_PLUGINS_DIR="/usr/share/elasticsearch/plugins"
    ES_LIB_PATH="/usr/share/elasticsearch/lib"

    if [ -x "$(command -v sudo)" ]; then
        SUDO_CMD="sudo"
        echo "This script maybe require your root password for 'sudo' privileges"
    fi

    ES_INSTALL_TYPE="rpm/deb"
fi

if [ $SUDO_CMD ]; then
    if ! [ -x "$(command -v $SUDO_CMD)" ]; then
        echo "Unable to locate 'sudo' command. Quit."
        exit 1
    fi
fi

if $SUDO_CMD test -f "$ES_CONF_FILE"; then
    :
else
    echo "Unable to determine elasticsearch config directory. Quit."
    exit -1
fi

if [ ! -d $ES_BIN_DIR ]; then
	echo "Unable to determine elasticsearch bin directory. Quit."
	exit -1
fi

if [ ! -d $ES_PLUGINS_DIR ]; then
	echo "Unable to determine elasticsearch plugins directory. Quit."
	exit -1
fi

if [ ! -d $ES_LIB_PATH ]; then
	echo "Unable to determine elasticsearch lib directory. Quit."
	exit -1
fi

ES_CONF_DIR=$(dirname "${ES_CONF_FILE}")
ES_CONF_DIR=`cd "$ES_CONF_DIR" ; pwd`

if [ ! -d "$ES_PLUGINS_DIR/search-guard-6" ]; then
  echo "Search Guard plugin not installed. Quit."
  exit -1
fi

ES_VERSION=("$ES_LIB_PATH/elasticsearch-*.jar")
ES_VERSION=$(echo $ES_VERSION | sed 's/.*elasticsearch-\(.*\)\.jar/\1/')

SG_VERSION=("$ES_PLUGINS_DIR/search-guard-6/search-guard-6-*.jar")
SG_VERSION=$(echo $SG_VERSION | sed 's/.*search-guard-6-\(.*\)\.jar/\1/')

OS=$(sb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1 || uname -om)
echo "Elasticsearch install type: $ES_INSTALL_TYPE on $OS"
echo "Elasticsearch config dir: $ES_CONF_DIR"
echo "Elasticsearch config file: $ES_CONF_FILE"
echo "Elasticsearch bin dir: $ES_BIN_DIR"
echo "Elasticsearch plugins dir: $ES_PLUGINS_DIR"
echo "Elasticsearch lib dir: $ES_LIB_PATH"
echo "Detected Elasticsearch Version: $ES_VERSION"
echo "Detected Search Guard Version: $SG_VERSION"

if $SUDO_CMD grep --quiet -i searchguard $ES_CONF_FILE; then
  echo "$ES_CONF_FILE seems to be already configured for Search Guard. Quit."
  exit -1
fi

set +e

read -r -d '' SG_ADMIN_CERT << EOM
-----BEGIN CERTIFICATE-----
MIID2jCCAsKgAwIBAgIBBTANBgkqhkiG9w0BAQUFADCBlTETMBEGCgmSJomT8ixk
ARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4YW1wbGUxGTAXBgNVBAoMEEV4YW1w
bGUgQ29tIEluYy4xJDAiBgNVBAsMG0V4YW1wbGUgQ29tIEluYy4gU2lnbmluZyBD
QTEkMCIGA1UEAwwbRXhhbXBsZSBDb20gSW5jLiBTaWduaW5nIENBMB4XDTE2MDUw
NDIwNDUzNFoXDTE4MDUwNDIwNDUzNFowTTELMAkGA1UEBhMCREUxDTALBgNVBAcT
BFRlc3QxDzANBgNVBAoTBmNsaWVudDEPMA0GA1UECxMGY2xpZW50MQ0wCwYDVQQD
EwRraXJrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh0WcM8BpT9hb
y6BMzXg7tl5zhfq2pu61j0+n8SPiSa90g89Zks4sU3h6vNj+QO0S3TFC30BTH0D3
61l4AeKn4rLg0rfgj6HGUX1KqoRpTBtpfC4CTK+fLZ9AB72rrzU3ohpcl8tEocR2
wyikCjK1rP0S/pvJCd1ZJ/zRTWylgNNg0Bx5s2Avkl01HQHI+0TQ2Tuaqn81lhqc
NzjbADXQxMVa3xE5YaDbWTFbuDoEINWGPMZisku4bElgJCYkN/2mF91zS2dfaZ0X
qaxpCB2k+t+CAY103kgM1nozpX5yfCGBG2r6lFAZL0o7Biiit170STiRBWUFsgSl
DUKjkd8/owIDAQABo3wwejAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFAAHm5Sk4Puz5rov
VzCej/+/dmBEMB8GA1UdIwQYMBaAFDUDIxMwMCEfj73z317BsKkgiCywMA0GCSqG
SIb3DQEBBQUAA4IBAQBp5INg3U9Z3fD/LL5TbAJGvfhKoUzOiKl3PD81Q7Ga26rS
f+LK7vudP/ejxfyZCQhTFDhZwLRiylk+ibSokjSIIUobNRxZpqp48pvPO79mlbq2
PZL0sgppZ/h2yk6OuZ+oBSDfFgyPNNgjxZl1xiEurvotwiQ93xmVyVdwli8ylqAr
BQlILEDUbYi9xPP3TRW2CBhWZ7vN9c+60Xe3URkTvS747APehWJc+kS06TgOk4kz
BLAZ7KkqbcrobCXJf2Vr5KLs6l6Ja1Gd/wNGGdPe4C1Hh2fnArjNCfeM9gy35mx7
vygyJSGvXqNLoYcu53yJ+YWSkUVwecjl0mVWwbTj
-----END CERTIFICATE-----
EOM

read -r -d '' SG_ADMIN_CERT_KEY << EOM
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCHRZwzwGlP2FvL
oEzNeDu2XnOF+ram7rWPT6fxI+JJr3SDz1mSzixTeHq82P5A7RLdMULfQFMfQPfr
WXgB4qfisuDSt+CPocZRfUqqhGlMG2l8LgJMr58tn0AHvauvNTeiGlyXy0ShxHbD
KKQKMrWs/RL+m8kJ3Vkn/NFNbKWA02DQHHmzYC+SXTUdAcj7RNDZO5qqfzWWGpw3
ONsANdDExVrfETlhoNtZMVu4OgQg1YY8xmKyS7hsSWAkJiQ3/aYX3XNLZ19pnRep
rGkIHaT634IBjXTeSAzWejOlfnJ8IYEbavqUUBkvSjsGKKK3XvRJOJEFZQWyBKUN
QqOR3z+jAgMBAAECggEAIwwyEGaF4p4YCoYZ4BKKxhFqtQfkUxP+DoeA58V4V8cR
1STf/F1Wtrm8czl1hrTl8lFVFirAXpSip2Oi6DolbWMTRQVHNW+gxnRD6DIuZf2k
MvxotB28jEF6gYbu+JI9O87AtsN/oLoaWy4ockv5LjzTswwB5oBnHSkvwXOo3duF
Gs92co+iS6krHHzuPcwHKYggaYTJoAv1QInvDhVg0ckZcdk9D1qOG30znEOdmRo8
TGsvEG50ucCalAwE1Mpy0Az0JOATtgbPnTR85GLG9L50Z7EvN1/ARnJ5Sh7EJHgP
P1ESmqcILNar64FvdQNxz9ayUpdBkfPyWkeACLHuAQKBgQDVukt7USbcb3JojM02
ydJZFygGoRByhOXjhMM5eYQbfS5WzxLLw40/a3pQmfm3uWp3qP7rki7i/Lg3jU9Q
6zHWZzE/NQ+ARNKEkXErDDjxAWob5vX1gz4YVwnxlEAWVnUS8CjB7Pd1umA3PK1Y
peMyS5R8lSOejeUytegjEhaSwQKBgQCiBtoUug8Jg1rd2KHs6bV0HcCwLNB4k5Bt
fNwJfmz5vWY9XohOAhH1c9i1OFCsdgPKoeYMY6H48/q/8rTrh+g4tLd6UQSUc+91
D9jpTQKf9cI2MDe/ZHZUpzL9q87CYLXXp2yl31iYixBbrkNXPQqFNoCG4V2+kSI3
VAI9Mcc/YwKBgHw9tH02GoIP4xD1sKGFxtp1RJY98MKxkLWmypnRksMsDND3xPRg
c+6G+u5545kylrqCqdWk/86BnFDmu1HNtwXsrMsSfDVTTJE1vvSIQV2QNe+MXjRf
G6yohCZDyNFzZtEgfIDm0J9GPYI+qoIaxKzLFMErLS6RS8gjyJMCg87BAoGAFSP9
umyYX65i4cVNQ2MvCMqFBLekL8dZNd/vudFkGKXMvD8kW8FLZJJL+UEyzX3Metjq
8jzhumDjG75oOr8N3rA9rFj71v7VhJmfvLkOmZ5wS6+45mEOS3dRYOXU4WnK8Ctp
Mq9UmPq0FLJFGRHe2IjG9lJbb+zx4PQ2IpPnIm8CgYEA1NCCi21Pc47qVv+cXE6e
lb/nrNGWRpdzCiE8ey2Roq97AAMMuy3jpQGaqte5CXB7uYDpfJMi0nO8xLiUWqYi
WJm6vCqgAm4pIAQECVy4EbhpUsot2r3YgO8I4I+QEh45REfyEHJiFr6Tp3moCI68
XrtWOrr6+mjXUwEwG9nlkf0=
-----END PRIVATE KEY-----
EOM

read -r -d '' NODE_CERT << EOM
-----BEGIN CERTIFICATE-----
MIIEHDCCAwSgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBlTETMBEGCgmSJomT8ixk
ARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4YW1wbGUxGTAXBgNVBAoMEEV4YW1w
bGUgQ29tIEluYy4xJDAiBgNVBAsMG0V4YW1wbGUgQ29tIEluYy4gU2lnbmluZyBD
QTEkMCIGA1UEAwwbRXhhbXBsZSBDb20gSW5jLiBTaWduaW5nIENBMB4XDTE2MDUw
NDIwNDUyOFoXDTE4MDUwNDIwNDUyOFowVjELMAkGA1UEBhMCREUxDTALBgNVBAcT
BFRlc3QxDTALBgNVBAoTBFRlc3QxDDAKBgNVBAsTA1NTTDEbMBkGA1UEAxMSbm9k
ZS0wLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mxj+XriXAJD6oUZNFmSNQh6CDm/mnLr4kTVEaKwtSIbiOmcLWvQlheVjHwjer+E5
VSgwDXbnV/iwbohDoFwA/+jraUvrSKAE4F5bb7vLWV2EMGOBfaA74YDRE+jhVURj
2zdBT7Bhsv8GATtkM35U6tXWy1xH7sbMRMZ5GwKT2z6+nVKk9AMLB6ddQjOZECmN
c3D0yKECZ3TjniH9W5VS+OeIFCrojovHfmB6QUziPPayhHAUVMoGDltQp3LCkbmq
//W3/AkJHCL30ZfPEt65jnVXTIGTnYMLgarmMVHpUrwD5u7qir5fgBQnltX6+NzK
JohD1GaT9wllVpE1D0hR/QIDAQABo4G0MIGxMA4GA1UdDwEB/wQEAwIFoDAJBgNV
HRMEAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU
faHeEk2u1nmdz6hXfjAIi7qOWdgwHwYDVR0jBBgwFoAUNQMjEzAwIR+PvfPfXsGw
qSCILLAwNQYDVR0RBC4wLIISbm9kZS0wLmV4YW1wbGUuY29tgglsb2NhbGhvc3SH
BH8AAAGIBSoDBAUFMA0GCSqGSIb3DQEBBQUAA4IBAQAK+oWmOL1bQCIkGtax06KI
Iy+17B5Ld/Cqu0E6rF/qBvOQ4ceODt/BecQ58/WeHB+7F5HvCjWfoYlPQMNlvNjN
JYgNfUSBE0rdvMVL79DOUQR2WblbzjOOE++ViNTOzqhjdc+gFcvh1hRh649FYeVv
kp4G5fNNzsNQzL8ZAIypc1korMOycs6GmJCP3GXLpoYBSLdh0X9f6z0JUAiciTZy
98TQyiD4Hw6uBIddyVA1NSzyEL/lHlX+ffGXMgL0YqfbYVQarMIqlQ2vnOXnW6gP
3RQyavhymHEaO3cPzT2m3CCjavej0kTBhHD9uiZKA/hEWTxQp7TFoN8ERYbnN8Uv
-----END CERTIFICATE-----
EOM

read -r -d '' NODE_KEY << EOM
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCbGP5euJcAkPqh
Rk0WZI1CHoIOb+acuviRNURorC1IhuI6Zwta9CWF5WMfCN6v4TlVKDANdudX+LBu
iEOgXAD/6OtpS+tIoATgXltvu8tZXYQwY4F9oDvhgNET6OFVRGPbN0FPsGGy/wYB
O2QzflTq1dbLXEfuxsxExnkbApPbPr6dUqT0AwsHp11CM5kQKY1zcPTIoQJndOOe
If1blVL454gUKuiOi8d+YHpBTOI89rKEcBRUygYOW1CncsKRuar/9bf8CQkcIvfR
l88S3rmOdVdMgZOdgwuBquYxUelSvAPm7uqKvl+AFCeW1fr43MomiEPUZpP3CWVW
kTUPSFH9AgMBAAECggEAP1pcPTDFbZPK7Kmcv3LfSIzRrzgCSS8ObbIGeYMrFB8U
tap1tvdXhHQIoxqqa8lh8+jwh+9z3DlXSC8dAJnURrRLxL0gJJBIraWdT+yzyZMr
deCPelNDYn+N58YOlRfUeiz93qE7pzQIreQmr+oAodQrYvIU5/IIamdv/Jp27uzz
JZQuJcNyIeg/R+fGNywKtNocQNRpoztTzQ5KvyprSilfSJv9V1jz5plAnHI7F/6w
vau8vF5Z8S83W2raEaRMMvg1sOxTHPd5xYBwOvzNgpLZxs+jGX+j8z/EkwTWxOpB
raDwVjBhmIYybQuzk76ev5ZhhQnC8SOu7wbK8E6NQQKBgQDsNrxt319Cej98Nr7i
NSxY6jNd6rqT5dal7nMI29VJaaciz5R++Xyv9D1HHr670bYL0FxRWhzY0ZzU9ERa
ohklDQjdyurYSaKaMNhTlF/Flq7O2mPd6Jb4RQirl6ryEig2ZqUXRZyh17hNWCAO
5T/jQ5kA1W7WzA3y9bu3gvjfFQKBgQCoFtaYc3hF4/dGDA7Pdh3fluhkXY8eFdqI
9kuZFRy3j7RI3bxIO6loI+/VzbRs5UwBQtQHwUAKmtAwR855t+jqjt+v+F8L1u7Z
Uyb5ooTqX2VojAmIZ+BCt8m5vdgQYtJvMUYAHAX9wkuk0IGMrpaMIdQwH9BSF7KE
4qTahxMhSQKBgCZ1KuyAh5PdL2TbzOwrWBMJ3l8WDlZx/yZ40gXJNMqFBw8l2Llr
iR9klm1z1f3iQM9flwgvsa6jQfNx6YcQCSP9IUpq9R1Nr8mG1lGVQJp80+0dpVDF
w36cTrMROGW9CwsAXzSQwtWet4TwKhgCvwoTQV/fX/JcupCp7WwNSNOZAoGACAcf
NKS/J8dddfD5fBsODjGs4648OZmdmFD7B1KkzneEir5cUa7XxmuA9tseNN02phDF
A6HNJzSBoOytBc8sxpcQQ90+3NflDGgWQnHqmy73LukRQ3yCj20rqz1P5mhx2HGo
ADVWa+otpq92oHtuIT80XSAH2QPcuNACQ5WT6lECgYAml7h3TJqFfwJ6bDEiFr2p
teX05VfE7Ls5H7UjNlr10S9YxFQV5bkzeVSaH6vQpijnDSYp2iLEcQAaZO9C7Tv8
79WJhRdSi4scHOmePAlTWBaK0hMHPwaPfw5NItVgk9e0/kj842PWWmIDkdVClrD8
/ZUD5qzu06rsSORq8Yjyhw==
-----END PRIVATE KEY-----
EOM

read -r -d '' CA_CHAIN << EOM
-----BEGIN CERTIFICATE-----
MIIEBzCCAu+gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBjzETMBEGCgmSJomT8ixk
ARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4YW1wbGUxGTAXBgNVBAoMEEV4YW1w
bGUgQ29tIEluYy4xITAfBgNVBAsMGEV4YW1wbGUgQ29tIEluYy4gUm9vdCBDQTEh
MB8GA1UEAwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENBMB4XDTE2MDUwNDIwNDUy
NloXDTI2MDUwNDIwNDUyNlowgZUxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJ
kiaJk/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSQw
IgYDVQQLDBtFeGFtcGxlIENvbSBJbmMuIFNpZ25pbmcgQ0ExJDAiBgNVBAMMG0V4
YW1wbGUgQ29tIEluYy4gU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBALt5tiuCoGls5xRSU+j2tUhpqjnjRdjC9KcHbus90J6ZUucc9b14
sP4+GwzFKWy0P95gUvdb3q1NfLz8GFXgJr2WL8q01rwHrWarPwhCNmjIKfrLw2R9
C8vksV4q1NwfSScrxZ+c6fL3Pkd1oFBTNSoeBQRhqEE3b/Iqe/sFP4W5U4gXK8ZF
RV00HTzgVqDCNHd20mtE792x9qk+7dXayMJmANw1nD9fSeeRcjkub80flZ3h0QNW
ILWC7v6RuaIjnO2st+NbgcGfD99rR2cinFol7bfJSVfw8SdyH9w8vWESN5hZgIRv
arxcDHEDdCXJRcEjWWQdkDhD1VXZISoSoWkCAwEAAaNmMGQwDgYDVR0PAQH/BAQD
AgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFDUDIxMwMCEfj73z317B
sKkgiCywMB8GA1UdIwQYMBaAFFEDmaGN4tE8OTNLv6Cob4xj0wS3MA0GCSqGSIb3
DQEBBQUAA4IBAQB6CpUq3ixUhAT55B2lynIqv42boFcbxiPNARCKt6E4LJZzeOJP
ystyQROdyXs6q8pOjauXVrURHnpN0Jh4eDKmGrEBvcBxvsW5uFV+EzWhlP0mYC4B
g/aHwrUkQ4Py03rczsu9MfkqoL0csQkxZQLTFeZZqvA3lcjwr2FiYHvpTvV9gSXZ
vMmqHB5atHr1OiQvPzQeowHz923a8HLqFeF1CWv9wwD+iFNUpM0cr9TDUXVbLSMy
nU0wDDi5eeIWrPiIXE7gbAzRiVXEHRj9RtszD1G/ZZ/hHb3qmydbzGjvvJmPa6MX
iVmPM0KHm2GgAR7V8fyANot9B1HoBoAvaGnO
-----END CERTIFICATE-----
EOM

read -r -d '' ROOT_CA << EOM
-----BEGIN CERTIFICATE-----
MIID/jCCAuagAwIBAgIBATANBgkqhkiG9w0BAQUFADCBjzETMBEGCgmSJomT8ixk
ARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4YW1wbGUxGTAXBgNVBAoMEEV4YW1w
bGUgQ29tIEluYy4xITAfBgNVBAsMGEV4YW1wbGUgQ29tIEluYy4gUm9vdCBDQTEh
MB8GA1UEAwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENBMB4XDTE2MDUwNDIwNDUy
NloXDTI2MDUwNDIwNDUyNlowgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJ
kiaJk/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEw
HwYDVQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1w
bGUgQ29tIEluYy4gUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKcNMLJ1/LIAAr/SW+guFsZH8sxtY1MpxwjEPbPvQfXp0chNqqUgN87z6wLi
jLeYfoj+P5Boc0BqvXq0XZGL/Oi3ObCmUdKUoFcK7ULra19HgoIwpUo9bcV3EEHt
xFw6e67HwPvtS7oRbSbsXPA4kjM93JzEhedP1V23vGZO8P9Avfi8XfC9yplzAg58
phkf7K9XGX0+XBpOj88bPjCsg2i5ya9na1P2V9heDGcRLkQHO6XNrdQjzIvOCNIj
ouNb71VKOTx6eehOQZktXGxRrHo9qkPKCOkStK30ARjK6YHchrECbU+tlBQ2/HGx
AcuWusCywqTAX9N1jdfSPwBUZ3MCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFFEDmaGN4tE8OTNLv6Cob4xj0wS3MB8G
A1UdIwQYMBaAFFEDmaGN4tE8OTNLv6Cob4xj0wS3MA0GCSqGSIb3DQEBBQUAA4IB
AQA3SQm3Axz0HfIcFH2qJ/kkUDHs70gzURWPbHQqFRTc+p1nXT8flcWDqAEp7hMV
WCxq6rf+Nj9Ej4eJ4RWumkF2UyEnUR+YjPp4gX/k4b4+zOsGQCvpP/LJ8Eg1gIz6
c/Lin1vu0ddpGZMI+pPVym7MNkxnKSM2TyOfj2AOrjD5SHzc3A9avjrWYdHOF3jr
F9JxfjX4rzmwh8SgJySQKjtKubS/m4bafrJ7ccFCLXxberWxUl3J4QMRNaxzLUaz
qNwhnLTw+/0ZhHgW8hQ5L0xhdrqQERp3Rw6bhLOBL6AtaoxjaWHK2Weps6wZ4Cjf
ZRP/AFlscD6hWl22tRqOt7xp
-----END CERTIFICATE-----
EOM

set -e

echo "$SG_ADMIN_CERT" | $SUDO_CMD tee "$ES_CONF_DIR/kirk.pem" > /dev/null
echo "$CA_CHAIN" | $SUDO_CMD tee -a "$ES_CONF_DIR/kirk.pem" > /dev/null
echo "$NODE_CERT" | $SUDO_CMD tee "$ES_CONF_DIR/esnode.pem" > /dev/null 
echo "$CA_CHAIN" | $SUDO_CMD tee -a "$ES_CONF_DIR/esnode.pem" > /dev/null 
echo "$ROOT_CA" | $SUDO_CMD tee "$ES_CONF_DIR/root-ca.pem" > /dev/null
echo "$NODE_KEY" | $SUDO_CMD tee "$ES_CONF_DIR/esnode-key.pem" > /dev/null
echo "$SG_ADMIN_CERT_KEY" | $SUDO_CMD tee "$ES_CONF_DIR/kirk-key.pem" > /dev/null

echo "" | $SUDO_CMD tee -a  $ES_CONF_FILE
echo "######## Start Search Guard Demo Configuration ########" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "# WARNING: revise all the lines below before you go into production" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "searchguard.ssl.transport.pemcert_filepath: esnode.pem" | $SUDO_CMD tee -a  $ES_CONF_FILE > /dev/null 
echo "searchguard.ssl.transport.pemkey_filepath: esnode-key.pem" | $SUDO_CMD tee -a  $ES_CONF_FILE > /dev/null 
echo "searchguard.ssl.transport.pemtrustedcas_filepath: root-ca.pem" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "searchguard.ssl.transport.enforce_hostname_verification: false" | $SUDO_CMD tee -a  $ES_CONF_FILE > /dev/null 
echo "searchguard.ssl.http.enabled: true" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "searchguard.ssl.http.pemcert_filepath: esnode.pem" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
echo "searchguard.ssl.http.pemkey_filepath: esnode-key.pem" | $SUDO_CMD tee -a  $ES_CONF_FILE > /dev/null 
echo "searchguard.ssl.http.pemtrustedcas_filepath: root-ca.pem" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "searchguard.allow_unsafe_democertificates: true" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
if [ "$initsg" == 1 ]; then
    echo "searchguard.allow_default_init_sgindex: true" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
fi
echo "searchguard.authcz.admin_dn:" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "  - CN=kirk,OU=client,O=client,L=test, C=de" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
echo "searchguard.audit.type: internal_elasticsearch" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
#echo "searchguard.audit.config.disabled_categories: ["AUTHENTICATED"]" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
echo "searchguard.enable_snapshot_restore_privilege: true" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
echo "searchguard.check_snapshot_restore_write_privileges: true" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
echo 'searchguard.restapi.roles_enabled: ["sg_all_access"]' | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null

if $SUDO_CMD grep --quiet -i "^cluster.name" $ES_CONF_FILE; then
	: #already present
else
    echo "cluster.name: searchguard_demo" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 
fi

if $SUDO_CMD grep --quiet -i "^network.host" $ES_CONF_FILE; then
	: #already present
else
    echo "network.host: 0.0.0.0" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
fi

if $SUDO_CMD grep --quiet -i "^discovery.zen.minimum_master_nodes" $ES_CONF_FILE; then
	: #already present
else
    echo "discovery.zen.minimum_master_nodes: 1" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
fi

if $SUDO_CMD grep --quiet -i "^node.max_local_storage_nodes" $ES_CONF_FILE; then
	: #already present
else
    echo 'node.max_local_storage_nodes: 3' | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
fi

if [ -d "$ES_PLUGINS_DIR/x-pack" ];then
	echo "xpack.security.enabled: false" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
	echo "xpack.monitoring.enabled: true" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
	echo "xpack.ml.enabled: false" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
	echo "xpack.graph.enabled: false" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
	echo "xpack.watcher.enabled: false" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null
fi

echo "######## End Search Guard Demo Configuration ########" | $SUDO_CMD tee -a $ES_CONF_FILE > /dev/null 

$SUDO_CMD chmod +x "$ES_PLUGINS_DIR/search-guard-6/tools/sgadmin.sh"

ES_PLUGINS_DIR=`cd "$ES_PLUGINS_DIR" ; pwd`

echo "### Success"
echo "### Execute this script now on all your nodes and then start all nodes"

if [ "$initsg" == 0 ]; then
	echo "#!/bin/bash" | $SUDO_CMD tee sgadmin_demo.sh > /dev/null 
	echo $SUDO_CMD "$ES_PLUGINS_DIR/search-guard-6/tools/sgadmin.sh" -cd "$ES_PLUGINS_DIR/search-guard-6/sgconfig" -icl -key "$ES_CONF_DIR/kirk-key.pem" -cert "$ES_CONF_DIR/kirk.pem" -cacert "$ES_CONF_DIR/root-ca.pem" -nhnv | $SUDO_CMD tee -a sgadmin_demo.sh > /dev/null
	$SUDO_CMD chmod +x sgadmin_demo.sh
	echo "### After the whole cluster is up execute: "
	$SUDO_CMD cat sgadmin_demo.sh | tail -1
	echo "### or run ./sgadmin_demo.sh"
fi

echo "### Then open https://localhost:9200 an login with admin/admin"
echo "### (Just ignore the ssl certificate warning because we installed a self signed demo certificate)"