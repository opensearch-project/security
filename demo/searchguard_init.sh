#!/bin/sh

export ES_CONF_DIR=/etc/elasticsearch
export ES_BIN_DIR=/usr/share/elasticsearch/bin
export ES_PLUGIN_DIR=/usr/share/elasticsearch/plugins

CONNECT_IP=10.0.3.111

#kirk is admin
#searchguard.authcz.admin_dn:
#  - "CN=kirk, OU=client, O=client, L=Test, C=DE"

sudo /etc/init.d/elasticsearch stop

echo "Install Search Guard SSL Plugin"
sudo $ES_BIN_DIR/plugin remove search-guard-ssl > /dev/null
sudo $ES_BIN_DIR/plugin remove search-guard-2 > /dev/null
sudo $ES_BIN_DIR/plugin install file:///vagrant/search-guard-ssl-2.2.1.7.zip 2>&1
#sudo $ES_BIN_DIR/plugin install com.floragunn/search-guard-ssl/$SG_SSL_VERSION 2>&1
echo "Install Search Guard Plugin"
#sudo $ES_BIN_DIR/plugin install com.floragunn/search-guard/$SG_VERSION 2>&1
sudo $ES_BIN_DIR/plugin install file:///vagrant/target/releases/search-guard-2-2.2.1.0-alpha3-SNAPSHOT.zip 2>&1

cp -vv /vagrant/search-guard-ssl/example-pki-scripts/truststore.jks $ES_PLUGIN_DIR/search-guard-2/sgconfig/truststore.jks
cp -vv /vagrant/search-guard-ssl/example-pki-scripts/kirk-keystore.jks $ES_PLUGIN_DIR/search-guard-2/sgconfig/kirk-keystore.jks
cp -vv /vagrant/search-guard-ssl/example-pki-scripts/kirk*.pem $ES_PLUGIN_DIR/search-guard-2/sgconfig/
cp -vv /vagrant/search-guard-ssl/example-pki-scripts/kirk*.p12 $ES_PLUGIN_DIR/search-guard-2/sgconfig/
cp -vv /vagrant/search-guard-ssl/example-pki-scripts/ca/root-ca.pem $ES_PLUGIN_DIR/search-guard-2/sgconfig/
cat /vagrant/search-guard-ssl/example-pki-scripts/kirk.crt.pem /vagrant/search-guard-ssl/example-pki-scripts/ca/chain-ca.pem > /vagrant/ch.pem

curl -Ss  \
  --insecure \
  -E /vagrant/ch.pem \
  --key  /vagrant/search-guard-ssl/example-pki-scripts/kirk.key.pem \
  https://$CONNECT_IP:9200/_searchguard/sslinfo?pretty

curl -Ss  \
  --insecure \
  -E /vagrant/ch.pem \
  --key  /vagrant/search-guard-ssl/example-pki-scripts/kirk.key.pem \
  https://$CONNECT_IP:9200/_searchguard/authinfo?pretty

curl -Ss  \
  --insecure \
  -E /vagrant/ch.pem \
  --key  /vagrant/search-guard-ssl/example-pki-scripts/kirk.key.pem \
  https://$CONNECT_IP:9200/_cluster/health?pretty=true&wait_for_nodes=3

curl -Ss  \
  --insecure \
  -E /vagrant/ch.pem \
  --key  /vagrant/search-guard-ssl/example-pki-scripts/kirk.key.pem \
  -XPOST https://$CONNECT_IP:9200/searchguard/blub -d '{}'

echo "Cluster seems up and running, now call sgadmin.sh"
export JAVA_OPTS='-Des.logger.level=DEBUG'

#Admin
chmod +x $ES_PLUGIN_DIR/search-guard-2/tools/sgadmin.sh
$ES_PLUGIN_DIR/search-guard-2/tools/sgadmin.sh -h $CONNECT_IP -cd /vagrant/demo/conf -ks $ES_PLUGIN_DIR/search-guard-2/sgconfig/kirk-keystore.jks -ts $ES_PLUGIN_DIR/search-guard-2/sgconfig/truststore.jks  -nhnv
echo "sgadmin.sh done, test it"

sleep 3

curl -Ss -XGET  \
  --insecure \
 -u spock:spock https://$CONNECT_IP:9200/_searchguard/authinfo?pretty

curl -Ss  \
  --insecure \
  -XPOST -u spock:spock https://$CONNECT_IP:9200/searchguard/blub -d '{}'

#curl -Ss -XPUT --insecure --cacert $ES_PLUGIN_DIR/search-guard-2/sgconfig/root-ca.pem -u spock:spock https://$CONNECT_IP:9200/vulcangov/kolinahr/1 -d '{"content":1}'
#curl -Ss -XPUT --insecure -u picard:picard https://$CONNECT_IP:9200/starfleet/ships/1 -d '{"content":1}'

#curl -Ss --insecure https://$CONNECT_IP:9200/_cluster/health?pretty
#curl -Ss --insecure https://$CONNECT_IP:9200/_searchguard/sslinfo?pretty
