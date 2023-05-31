# Developing with Docker

Docker is a powerful tool that can be used to quickly spin up an OpenSearch cluster. When you follow the steps to run [OpenSearch with Docker](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/docker/), you will find the Security Plugin already included in the basic distribution.

- [Developing with Docker](#developing-with-docker)
    - [Configuring Security](#configuring-security)
    - [Mounting Local Volumes](#mounting-local-volumes)
    - [Example docker-compose](#example-docker-compose)


## Configuring Security

By default, the Docker installation of OpenSearch does not enable the Security plugin. In order to enable Security development, you will need set `DISABLE_SECURITY_PLUGIN=false`, as well as change `DISABLE_INSTALL_DEMO_CONFIG` and `DISABLE_SECURITY_DASHBOARDS_PLUGIN`. This will install the demo certificates, and allow you to develop with realistic Security configurations. An example of a completely configured docker-compose file is shown below.

> Warning: You should never use the demo certificates for a production environment. Instead, you will need to follow the steps on [configuring security](https://opensearch.org/docs/latest/security/configuration/index/) before using the cluster for production.

### Mounting Local Volumes

In order to test development changes with an OpenSearch Docker-installation, you will need to mount the volumes in your docker-compose file.

To update your cluster to have local changes, follow these steps:

1. First you will need to make changes in your local `opensearch-project/security` repository. For this example, assume your fork is cloned into a directory called `security`.
2. After you make changes to your cloned repository, you will need to run `./gradlew assemble`. This will create a `.jar` file you can mount into the Docker container. The file will be located at `./security/build/distributions/opensearch-security-<OPENSEARCH_VERSION>.0-SNAPSHOT.jar`, where the `<OPENSEARCH_VERSION>` field is simply the OpenSearch distribution.
3. You will then need to navigate to your `docker-compose.yml` file where you are running you OpenSearch cluster from. For this example, let us assume this is in another directory called `opensearch-docker`.
4. Modify the compose file, so that in the `volumes:` section of each node configuration (the default configuration will have `opensearch-node1` and `opensearch-node2`), you have a new line which reads `~/security/build/distributions/opensearch-security-<OPENSEARCH_VERSION>.0-SNAPSHOT.jar:/usr/share/opensearch/plugins/opensearch-security/opensearch-security-<OPENSEARCH_VERSION>.0.jar`. This line should be added to the volumes section of all nodes in the compose file. You will not need to add it to the `opensearch-dashboards` section.
5. You can now restart the Docker container by running `docker-compose down -v` and `docker-compose up`. Your changes will now be live in the OpenSearch cluster instance.

### Example docker-compose

This is an example of a completely configured docker-compose file for a local installation of the 2.5.0 version of OpenSearch.

```
version: '3'
services:
  opensearch-node1:
    image: opensearchstaging/opensearch:2.5.0 # This is a image of the 2.5.0 distribution
    environment:
      - cluster.name=opensearch-cluster
      - node.name=opensearch-node1
      - discovery.seed_hosts=opensearch-node1,opensearch-node2
      - cluster.initial_master_nodes=opensearch-node1,opensearch-node2
      - bootstrap.memory_lock=true # along with the memlock settings below, disables swapping
      - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" # minimum and maximum Java heap size, recommend setting both to 50% of system RAM
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536 # maximum number of open files for the OpenSearch user, set to at least 65536 on modern systems
        hard: 65536
    ports:
      - 9200:9200
      - 9600:9600 # required for Performance Analyzer
    networks:
      - opensearch-net
  # volumes:
  #   - ./config/opensearch.yml:/usr/share/opensearch/config/opensearch.yml # These paths are relative to the location of the docker-compose file
  #   - ./config/esnode.pem:/usr/share/opensearch/config/esnode.pem
  #   - ./config/esnode-key.pem:/usr/share/opensearch/config/esnode-key.pem
  #   - ./config/root-ca.pem:/usr/share/opensearch/config/root-ca.pem
  #   - ./config/opensearch-security/audit.yml:/usr/share/opensearch/config/opensearch-security/audit.yml
  #   - ./config/opensearch-security/tenants.yml:/usr/share/opensearch/config/opensearch-security/tenants.yml
  #   - /OpenSearch-Snapshots:/mnt/snapshots # This is where your snapshots would be stored
  #   - /security/build/distributions/opensearch-security-2.5.0.0-SNAPSHOT.jar:/usr/share/opensearch/plugins/opensearch-security/opensearch-security-2.5.0.0.jar
  opensearch-node2: # This is the same settings as the opensearch-node1
    image: opensearchstaging/opensearch:2.5.0
    environment:
      - cluster.name=opensearch-cluster
      - node.name=opensearch-node2
      - discovery.seed_hosts=opensearch-node1,opensearch-node2
      - cluster.initial_master_nodes=opensearch-node1,opensearch-node2
      - bootstrap.memory_lock=true
      - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
   #volumes:
   #  - ./config/opensearch.yml:/usr/share/opensearch/config/opensearch.yml
   #  - ./config/esnode.pem:/usr/share/opensearch/config/esnode.pem
   #  - ./config/esnode-key.pem:/usr/share/opensearch/config/esnode-key.pem
   #  - ./config/root-ca.pem:/usr/share/opensearch/config/root-ca.pem
   #  - ./config/opensearch-security/audit.yml:/usr/share/opensearch/config/opensearch-security/audit.yml
   #  - ./config/opensearch-security/tenants.yml:/usr/share/opensearch/config/opensearch-security/tenants.yml
   #  - /OpenSearch-Snapshots:/mnt/snapshots
   #  - /security/build/distributions/opensearch-security-2.5.0.0-SNAPSHOT.jar:/usr/share/opensearch/plugins/opensearch-security/opensearch-security-2.5.0.0.jar
    networks:
      - opensearch-net
  opensearch-dashboards:
    image: opensearchstaging/opensearch-dashboards:2.5.0
    ports:
      - 5601:5601
    expose:
      - "5601"
    environment:
      OPENSEARCH_HOSTS: '["https://opensearch-node1:9200","https://opensearch-node2:9200"]'
    networks:
      - opensearch-net
   # volumes:
     # - ./opensearch_dashboards.yml:/usr/share/opensearch-dashboards/config/opensearch_dashboard.yml # this would mount a local dashboards configuration file
networks:
  opensearch-net:
```
