#!/bin/sh
#########
# No magic here, we just install java and openssl
#########
$script = <<SCRIPT
#########
# Setup search Guard
#########
echo "Setup search Guard"
/vagrant/demo/setup_sg.sh

IP=$(hostname -I | cut -f2 -d' ')

export JAVA_OPTS='-Des.logger.level=DEBUG'

echo "Start Elasticsearch on $(hostname)/$IP"
/etc/init.d/elasticsearch restart

while ! nc -z $IP 9200; do   
  sleep 0.1 # wait for 1/10 of the second before check again
done

echo "Elasticsearch now running on $(hostname)/$IP"

#curl -Ss --insecure https://$IP:9200/_cluster/health?pretty
#curl -Ss --insecure https://$IP:9200/_searchguard/sslinfo?pretty

SCRIPT
#End inline script

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

   config.vm.provision :hosts do |prov|
        prov.add_host '10.0.3.111', ['es1']
        prov.add_host '10.0.3.112', ['es2']
        prov.add_host '10.0.3.113', ['es3']
        prov.add_host '10.0.3.114', ['client']
   end

   config.vm.define "es1" do |es1|
        es1.vm.box = "ubuntu/trusty64"
        es1.vm.hostname = "es1"
        es1.vm.network "private_network", ip: "10.0.3.111"
        es1.vm.provision "shell", path: "demo/deps_install.sh"
        es1.vm.provision "shell", inline: 'echo "export SSLNAME=node-0-keystore.jks" >> ~/.profile'
        es1.vm.provision "shell", inline: 'echo "export OPENSSL=true" >> ~/.profile'
        es1.vm.provision "shell", inline: $script
        es1.vm.provider "virtualbox" do |v|
                     v.memory = 768 
                     v.cpus = 2
             end
   end

   config.vm.define "es2" do |es2|
        es2.vm.box = "ubuntu/trusty64"
        es2.vm.hostname = "es2"
        es2.vm.network "private_network", ip: "10.0.3.112"
        es2.vm.provision "shell", path: "demo/deps_install.sh"
        es2.vm.provision "shell", inline: 'echo "export SSLNAME=node-1-keystore.jks" >> ~/.profile'
        es2.vm.provision "shell", inline: 'echo "export OPENSSL=true" >> ~/.profile'
        es2.vm.provision "shell", inline: $script
        es2.vm.provider "virtualbox" do |v|
                     v.memory = 768 
                     v.cpus = 2
             end
   end

   config.vm.define "es3" do |es3|
        es3.vm.box = "ubuntu/trusty64"
        es3.vm.hostname = "es3"
        es3.vm.network "private_network", ip: "10.0.3.113"
        es3.vm.provision "shell", path: "demo/deps_install.sh"
        es3.vm.provision "shell", inline: 'echo "export SSLNAME=node-2-keystore.jks" >> ~/.profile'
        es3.vm.provision "shell", inline: 'echo "export OPENSSL=false" >> ~/.profile'
        es3.vm.provision "shell", inline: $script
        es3.vm.provider "virtualbox" do |v|
                     v.memory = 768 
                     v.cpus = 2
             end
   end
   
   config.vm.define "client" do |client|
        client.vm.box = "ubuntu/trusty64"
        client.vm.hostname = "client"
        client.vm.network "private_network", ip: "10.0.3.114"
        client.vm.provision "shell", path: "demo/deps_install.sh"
        client.vm.provision "shell", path: "demo/searchguard_init.sh"
        client.vm.provider "virtualbox" do |v|
                     v.memory = 768 
                     v.cpus = 2
             end
   end

end
