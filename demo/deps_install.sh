#!/bin/sh
export DEBIAN_FRONTEND=noninteractive
export ES_CONF_DIR=/etc/elasticsearch
export ES_BIN_DIR=/usr/share/elasticsearch/bin
export ES_PLUGIN_DIR=/usr/share/elasticsearch/plugins

if [ ! -f $ES_CONF_DIR/elasticsearch.yml ]
then
    echo "Update packages"
	sudo killall -9 java > /dev/null 2>&1
	wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - > /dev/null 2>&1
	echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list > /dev/null 2>&1
	sudo apt-get -yqq update > /dev/null 2>&1
	#echo "Install guest additions"
	#sudo apt-get -yqq install virtualbox-guest-additions-iso > /dev/null 2>&1
	echo "Prepare Java installation"
	echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo /usr/bin/debconf-set-selections > /dev/null 2>&1
	sudo apt-get -yqq install curl software-properties-common > /dev/null 2>&1
	sudo add-apt-repository -y ppa:webupd8team/java > /dev/null 2>&1
	sudo apt-get -yqq update > /dev/null 2>&1
	echo "Install Oracle Java 8, libapr1 and openssl"
	sudo apt-get -yqq install haveged libapr1 openssl wget git oracle-java8-installer oracle-java8-unlimited-jce-policy > /dev/null 2>&1
	#sudo apt-get -yqq install autoconf libtool libssl-dev libkrb5-dev python-dev python-pip haveged openssl wget git oracle-java8-installer oracle-java8-unlimited-jce-policy > /dev/null 2>&1
	#sudo apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" krb5-user > /dev/null 2>&1
	# entropy generator
	#haveged -w 1024 > /dev/null 2>&1
else
    echo "Packages and deps already installed"
    #########
	# Install elasticsearch (from official repo)
	# https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-repositories.html
	#########
	echo "Install Elasticsearch, but don't start it yet"
	sudo apt-get -yqq update > /dev/null 2>&1
	sudo apt-get install -yqq elasticsearch=2.2.1 > /dev/null 2>&1
    echo "Elasticsearch installed but not yet started"
fi





