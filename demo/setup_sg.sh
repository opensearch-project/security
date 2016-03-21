function insertAfter # file line newText
{
   local file="$1" line="$2" newText="$3"
   sed -i -e "/^$line$/a"$'\\\n'"$newText"$'\n' "$file"
}

SG_SSL_VERSION=2.2.1.7
SG_VERSION=2.2.1.0-alpha3

export ES_CONF_DIR=/etc/elasticsearch
export ES_BIN_DIR=/usr/share/elasticsearch/bin
export ES_PLUGIN_DIR=/usr/share/elasticsearch/plugins
export SSLNAME=node-0-keystore.jks
export OPENSSL=false

if [ ! -f /vagrant/search-guard-ssl/pom.xml ]
then
    echo "Gen certs"
    cd /vagrant
    git clone https://github.com/floragunncom/search-guard-ssl.git
    cd /vagrant/search-guard-ssl/example-pki-scripts
    ./example.sh > /dev/null 2>&1
fi

cd /tmp

NETTY_NATIVE_VERSION=1.1.33.Fork12
NETTY_NATIVE_CLASSIFIER=linux-x86_64
wget -O netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar https://search.maven.org/remotecontent?filepath=io/netty/netty-tcnative/$NETTY_NATIVE_VERSION/netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar > /dev/null 2>&1

echo "Install Search Guard SSL Plugin"
sudo $ES_BIN_DIR/plugin remove search-guard-ssl > /dev/null
sudo $ES_BIN_DIR/plugin remove search-guard-2 > /dev/null
#sudo $ES_BIN_DIR/plugin install file:///vagrant/search-guard-ssl-2.2.1.7.zip 2>&1
sudo $ES_BIN_DIR/plugin install com.floragunn/search-guard-ssl/$SG_SSL_VERSION 2>&1
echo "Install Search Guard Plugin"
sudo $ES_BIN_DIR/plugin install com.floragunn/search-guard-2/$SG_VERSION 2>&1
#sudo $ES_BIN_DIR/plugin install file:///vagrant/target/releases/search-guard-2-2.2.1.0-alpha3-SNAPSHOT.zip 2>&1
sudo $ES_BIN_DIR/plugin install lmenezes/elasticsearch-kopf
sudo $ES_BIN_DIR/plugin install mobz/elasticsearch-head

echo "Install netty-tcnative for native Openssl support"
cp netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar $ES_PLUGIN_DIR/search-guard-ssl/

#SSL setup
echo "searchguard.ssl.transport.enabled: true" > $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.keystore_filepath: $SSLNAME" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.truststore_filepath: truststore.jks" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.enforce_hostname_verification: false" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.enabled: true" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.keystore_filepath: $SSLNAME" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.truststore_filepath: truststore.jks" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.http.enable_openssl_if_available: $OPENSSL" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.ssl.transport.enable_openssl_if_available: $OPENSSL" >> $ES_CONF_DIR/elasticsearch.yml

#SG Setup
echo "security.manager.enabled: false" >> $ES_CONF_DIR/elasticsearch.yml
echo "searchguard.authcz.admin_dn:" >> $ES_CONF_DIR/elasticsearch.yml
echo '  - "CN=kirk, OU=client, O=client, L=Test, C=DE"' >> $ES_CONF_DIR/elasticsearch.yml


#Misc setup
echo "network.host: _eth1:ipv4_" >> $ES_CONF_DIR/elasticsearch.yml
echo "discovery.zen.ping.unicast.hosts: 10.0.3.113,10.0.3.112,10.0.3.111" >> $ES_CONF_DIR/elasticsearch.yml
echo "discovery.zen.ping.multicast.enabled: false" >> $ES_CONF_DIR/elasticsearch.yml

#Logging
insertAfter $ES_CONF_DIR/logging.yml 4 "  com.floragunn: DEBUG"

cp -vv /vagrant/search-guard-ssl/example-pki-scripts/$SSLNAME $ES_CONF_DIR/
cp -vv /vagrant/search-guard-ssl/example-pki-scripts/truststore.jks $ES_CONF_DIR/