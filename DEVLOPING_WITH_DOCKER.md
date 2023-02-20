# Developing with Docker

Docker is a powerful tool that can be used to quickly spin up an OpenSearch cluster. When you follow the steps to run [OpenSearch with Docker](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/docker/), you will find the Security Plugin already included in the basic distribution. 

- [Developing with Docker](#developing-with-docker)
    - [Configuring Security](#configuring-security)
    - [Mounting Local Volumes](#mounting-local-volumes)
    

## Configuring Security 

By default, the Docker installation of OpenSearch does not enable the Security plugin. In order to enable Security development, you will need set `DISABLE_SECURITY_PLUGIN=false`. This will install the demo certificates, and allow you to develop with realistic Security configurations. 

> Warning: You should never use the demo certificates for a production environment. Instead, you will need to follow the steps on [configuring security](https://opensearch.org/docs/latest/security/configuration/index/) before using the cluster for production.

### Mounting Local Volumes 

In order to test development changes with an OpenSearch Docker-installation, you will need to mount the volumes in your Docker-compose file.  

To update your cluster to have local changes, follow these steps: 

1. First you will need to make changes in your local `opensearch-project/security` repository. For this example, assume your fork is cloned into a directory called `security`.
2. After you make changes to your cloned repository, you will need to run `./gradlew assemble`. This will create a `.jar` file you can mount into the Docker container. The file will be located at `./security/build/distributions/opensearch-security-<OPENSEARCH_VERSION>.0-SNAPSHOT.jar`, where the `<OPENSEARCH_VERSION>` field is simply the OpenSearch distribution. 
3. You will then need to navigate to your `docker-compose.yml` file where you are running you OpenSearch cluster from. For this example, let us assume this is in another directory called `opensearch-docker`. 
4. Modify the compose file, so that in the `volumes:` section of each node configuration (the default configuration will have `opensearch-node1` and `opensearch-node2`), you have a new line which reads `~/security/build/distributions/opensearch-security-<OPENSEARCH_VERSION>.0-SNAPSHOT.jar:/usr/share/opensearch/plugins/opensearch-security/opensearch-security-<OPENSEARCH_VERSION>.0.jar`. This line should be added to the volumes section of all nodes in the compose file. You will not need to add it to the `opensearch-dashboards` section. 
5. You can now restart the Docker container by running `docker-compose down -v` and `docker-compose up`. Your changes will now be live in the OpenSearch cluster instance. 
