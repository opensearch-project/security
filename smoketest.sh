#!/bin/bash
killall -9 java
shopt -s extglob
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

ES_VERSION=6.5.1
NETTY_NATIVE_VERSION=2.0.7.Final
NETTY_NATIVE_CLASSIFIER=non-fedora-linux-x86_64

rm -rf elasticsearch-$ES_VERSION
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ES_VERSION.tar.gz
tar -xzf elasticsearch-$ES_VERSION.tar.gz
rm -rf elasticsearch-$ES_VERSION.tar.gz
#wget -O netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar https://search.maven.org/remotecontent?filepath=io/netty/netty-tcnative/$NETTY_NATIVE_VERSION/netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar
mvn clean package -Penterprise -DskipTests > /dev/null 2>&1
PLUGIN_FILE=($DIR/target/releases/search-guard!(*sgadmin*).zip)
URL=file://$PLUGIN_FILE
echo $URL
elasticsearch-$ES_VERSION/bin/elasticsearch-plugin install -b $URL
RET=$?

if [ $RET -eq 0 ]; then
    echo Installation ok
else
    echo Installation failed
    exit -1
fi

#cp netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar elasticsearch-$ES_VERSION/plugins/search-guard-ssl/
rm -f netty-tcnative-$NETTY_NATIVE_VERSION-$NETTY_NATIVE_CLASSIFIER.jar

chmod +x elasticsearch-$ES_VERSION/plugins/search-guard-6/tools/install_demo_configuration.sh
./elasticsearch-$ES_VERSION/plugins/search-guard-6/tools/install_demo_configuration.sh -y -i
elasticsearch-$ES_VERSION/bin/elasticsearch &

while ! nc -z 127.0.0.1 9200; do
  sleep 0.1 # wait for 1/10 of the second before check again
done

sleep 10

RES="$(curl -Ss --insecure -XGET -u admin:admin 'https://127.0.0.1:9200/_searchguard/authinfo' -H'Content-Type: application/json' | grep roles)"

if [ -z "$RES" ]; then
  echo "failed"
  exit -1
else
  echo "$RES"
  echo ok
fi

killall java