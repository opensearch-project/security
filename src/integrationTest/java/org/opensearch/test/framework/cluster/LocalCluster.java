/*
* Copyright 2015-2021 floragunn GmbH
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

/*
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
* Modifications Copyright OpenSearch Contributors. See
* GitHub history for details.
*/

package org.opensearch.test.framework.cluster;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.rules.ExternalResource;

import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.plugins.Plugin;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuthFailureListeners;
import org.opensearch.test.framework.AuthzDomain;
import org.opensearch.test.framework.OnBehalfOfConfig;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.XffConfig;
import org.opensearch.test.framework.audit.TestRuleAuditLogSink;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.certificate.TestCertificates;

/**
* This class allows to you start and manage a local cluster in an integration test. In contrast to the
* OpenSearchIntegTestCase class, this class can be used in a composite way and allows the specification
* of the security plugin configuration.
*
* This class can be both used as a JUnit @ClassRule (preferred) or in a try-with-resources block. The latter way should
* be only sparingly used, as starting a cluster is not a particularly fast operation.
*/
public class LocalCluster extends ExternalResource implements AutoCloseable, OpenSearchClientProvider {

    private static final Logger log = LogManager.getLogger(LocalCluster.class);

    public static final String INIT_CONFIGURATION_DIR = "security.default_init.dir";

    protected static final AtomicLong num = new AtomicLong();

    private boolean sslOnly;

    private final List<Class<? extends Plugin>> plugins;
    private final ClusterManager clusterManager;
    private final TestSecurityConfig testSecurityConfig;
    private Settings nodeOverride;
    private final String clusterName;
    private final MinimumSecuritySettingsSupplierFactory minimumOpenSearchSettingsSupplierFactory;
    private final TestCertificates testCertificates;
    private final List<LocalCluster> clusterDependencies;
    private final Map<String, LocalCluster> remotes;
    private volatile LocalOpenSearchCluster localOpenSearchCluster;
    private final List<TestIndex> testIndices;

    private boolean loadConfigurationIntoIndex;

    private LocalCluster(
        String clusterName,
        TestSecurityConfig testSgConfig,
        boolean sslOnly,
        Settings nodeOverride,
        ClusterManager clusterManager,
        List<Class<? extends Plugin>> plugins,
        TestCertificates testCertificates,
        List<LocalCluster> clusterDependencies,
        Map<String, LocalCluster> remotes,
        List<TestIndex> testIndices,
        boolean loadConfigurationIntoIndex,
        String defaultConfigurationInitDirectory
    ) {
        this.plugins = plugins;
        this.testCertificates = testCertificates;
        this.clusterManager = clusterManager;
        this.testSecurityConfig = testSgConfig;
        this.sslOnly = sslOnly;
        this.nodeOverride = nodeOverride;
        this.clusterName = clusterName;
        this.minimumOpenSearchSettingsSupplierFactory = new MinimumSecuritySettingsSupplierFactory(testCertificates);
        this.remotes = remotes;
        this.clusterDependencies = clusterDependencies;
        this.testIndices = testIndices;
        this.loadConfigurationIntoIndex = loadConfigurationIntoIndex;
        if (StringUtils.isNoneBlank(defaultConfigurationInitDirectory)) {
            System.setProperty(INIT_CONFIGURATION_DIR, defaultConfigurationInitDirectory);
        }
    }

    public String getSnapshotDirPath() {
        return localOpenSearchCluster.getSnapshotDirPath();
    }

    @Override
    public void before() {
        if (localOpenSearchCluster == null) {
            for (LocalCluster dependency : clusterDependencies) {
                if (!dependency.isStarted()) {
                    dependency.before();
                }
            }

            for (Map.Entry<String, LocalCluster> entry : remotes.entrySet()) {
                InetSocketAddress transportAddress = entry.getValue().localOpenSearchCluster.clusterManagerNode().getTransportAddress();
                String key = "cluster.remote." + entry.getKey() + ".seeds";
                String value = transportAddress.getHostString() + ":" + transportAddress.getPort();
                log.info("Remote cluster '{}' added to configuration with the following seed '{}'", key, value);
                nodeOverride = Settings.builder().put(nodeOverride).putList(key, value).build();
            }
            start();
        }
    }

    @Override
    protected void after() {
        close();
    }

    @Override
    public void close() {
        System.clearProperty(INIT_CONFIGURATION_DIR);
        if (localOpenSearchCluster != null && localOpenSearchCluster.isStarted()) {
            try {
                localOpenSearchCluster.destroy();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                localOpenSearchCluster = null;
            }
        }
    }

    @Override
    public String getClusterName() {
        return clusterName;
    }

    @Override
    public InetSocketAddress getHttpAddress() {
        return localOpenSearchCluster.clientNode().getHttpAddress();
    }

    public int getHttpPort() {
        return getHttpAddress().getPort();
    }

    @Override
    public InetSocketAddress getTransportAddress() {
        return localOpenSearchCluster.clientNode().getTransportAddress();
    }

    /**
    * Returns a Client object that performs cluster-internal requests. As these requests are regard as cluster-internal,
    * no authentication is performed and no user-information is attached to these requests. Thus, this client should
    * be only used for preparing test environments, but not as a test subject.
    */
    public Client getInternalNodeClient() {
        return localOpenSearchCluster.clientNode().getInternalNodeClient();
    }

    /**
    * Returns a random node of this cluster.
    */
    public PluginAwareNode node() {
        return this.localOpenSearchCluster.clusterManagerNode().esNode();
    }

    /**
    * Returns all nodes of this cluster.
    */
    public List<LocalOpenSearchCluster.Node> nodes() {
        return this.localOpenSearchCluster.getNodes();
    }

    public LocalOpenSearchCluster.Node getNodeByName(String name) {
        return this.localOpenSearchCluster.getNodeByName(name);
    }

    public boolean isStarted() {
        return localOpenSearchCluster != null;
    }

    public List<TestSecurityConfig.User> getConfiguredUsers() {
        return testSecurityConfig.getUsers();
    }

    public Random getRandom() {
        return localOpenSearchCluster.getRandom();
    }

    private void start() {
        try {
            NodeSettingsSupplier nodeSettingsSupplier = minimumOpenSearchSettingsSupplierFactory.minimumOpenSearchSettings(
                sslOnly,
                nodeOverride
            );
            localOpenSearchCluster = new LocalOpenSearchCluster(
                clusterName,
                clusterManager,
                nodeSettingsSupplier,
                plugins,
                testCertificates
            );

            localOpenSearchCluster.start();

            if (loadConfigurationIntoIndex) {
                initSecurityIndex(testSecurityConfig);
            }

            try (Client client = getInternalNodeClient()) {
                for (TestIndex index : this.testIndices) {
                    index.create(client);
                }
            }

        } catch (Exception e) {
            log.error("Local ES cluster start failed", e);
            throw new RuntimeException(e);
        }
    }

    private void initSecurityIndex(TestSecurityConfig testSecurityConfig) {
        log.info("Initializing OpenSearch Security index");
        try (
            Client client = new ContextHeaderDecoratorClient(
                this.getInternalNodeClient(),
                Map.of(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true")
            )
        ) {
            testSecurityConfig.initIndex(client);
            triggerConfigurationReload(client);
        }
    }

    public void updateUserConfiguration(List<TestSecurityConfig.User> users) {
        try (
            Client client = new ContextHeaderDecoratorClient(
                this.getInternalNodeClient(),
                Map.of(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true")
            )
        ) {
            testSecurityConfig.updateInternalUsersConfiguration(client, users);
            triggerConfigurationReload(client);
        }
    }

    private static void triggerConfigurationReload(Client client) {
        ConfigUpdateResponse configUpdateResponse = client.execute(
            ConfigUpdateAction.INSTANCE,
            new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0]))
        ).actionGet();
        if (configUpdateResponse.hasFailures()) {
            throw new RuntimeException("ConfigUpdateResponse produced failures: " + configUpdateResponse.failures());
        }
    }

    public void triggerConfigurationReloadForCTypes(Client client, List<CType> cTypes, boolean ignoreFailures) {
        ConfigUpdateResponse configUpdateResponse = client.execute(
            ConfigUpdateAction.INSTANCE,
            new ConfigUpdateRequest(cTypes.stream().map(CType::toLCString).toArray(String[]::new))
        ).actionGet();
        if (!ignoreFailures && configUpdateResponse.hasFailures()) {
            throw new RuntimeException("ConfigUpdateResponse produced failures: " + configUpdateResponse.failures());
        }
    }

    public CertificateData getAdminCertificate() {
        return testCertificates.getAdminCertificateData();
    }

    public static class Builder {

        private final Settings.Builder nodeOverrideSettingsBuilder = Settings.builder();

        private boolean sslOnly = false;
        private final List<Class<? extends Plugin>> plugins = new ArrayList<>();
        private Map<String, LocalCluster> remoteClusters = new HashMap<>();
        private List<LocalCluster> clusterDependencies = new ArrayList<>();
        private List<TestIndex> testIndices = new ArrayList<>();
        private ClusterManager clusterManager = ClusterManager.DEFAULT;
        private TestSecurityConfig testSecurityConfig = new TestSecurityConfig();
        private String clusterName = "local_cluster";
        private TestCertificates testCertificates;

        private boolean loadConfigurationIntoIndex = true;

        private String defaultConfigurationInitDirectory = null;

        public Builder() {}

        public Builder dependsOn(Object object) {
            // We just want to make sure that the object is already done
            if (object == null) {
                throw new IllegalStateException("Dependency not fulfilled");
            }
            return this;
        }

        public Builder clusterManager(ClusterManager clusterManager) {
            this.clusterManager = clusterManager;
            return this;
        }

        /**
        * Starts a cluster with only one node and thus saves some resources during startup. This shall be only used
        * for tests where the node interactions are not relevant to the test. An example for this would be
        * authentication tests, as authentication is always done on the directly connected node.
        */
        public Builder singleNode() {
            this.clusterManager = ClusterManager.SINGLENODE;
            return this;
        }

        /**
        * Specifies the configuration of the security plugin that shall be used by this cluster.
        */
        public Builder config(TestSecurityConfig testSecurityConfig) {
            this.testSecurityConfig = testSecurityConfig;
            return this;
        }

        public Builder sslOnly(boolean sslOnly) {
            this.sslOnly = sslOnly;
            return this;
        }

        public Builder nodeSettings(Map<String, Object> settings) {
            settings.forEach((key, value) -> {
                if (value instanceof List) {
                    List<String> values = ((List<?>) value).stream().map(String::valueOf).collect(Collectors.toList());
                    nodeOverrideSettingsBuilder.putList(key, values);
                } else {
                    nodeOverrideSettingsBuilder.put(key, String.valueOf(value));
                }
            });

            return this;
        }

        /**
        * Adds additional plugins to the cluster
        */
        public Builder plugin(Class<? extends Plugin> plugin) {
            this.plugins.add(plugin);

            return this;
        }

        public Builder authFailureListeners(AuthFailureListeners listener) {
            testSecurityConfig.authFailureListeners(listener);
            return this;
        }

        /**
        * Specifies a remote cluster and its name. The remote cluster can be then used in Cross Cluster Search
        * operations with the specified name.
        */
        public Builder remote(String name, LocalCluster anotherCluster) {
            remoteClusters.put(name, anotherCluster);

            clusterDependencies.add(anotherCluster);

            return this;
        }

        /**
        * Specifies test indices that shall be created upon startup of the cluster.
        */
        public Builder indices(TestIndex... indices) {
            this.testIndices.addAll(Arrays.asList(indices));
            return this;
        }

        public Builder users(TestSecurityConfig.User... users) {
            for (TestSecurityConfig.User user : users) {
                testSecurityConfig.user(user);
            }
            return this;
        }

        public Builder audit(AuditConfiguration auditConfiguration) {
            if (auditConfiguration != null) {
                testSecurityConfig.audit(auditConfiguration);
            }
            if (auditConfiguration.isEnabled()) {
                nodeOverrideSettingsBuilder.put("plugins.security.audit.type", TestRuleAuditLogSink.class.getName());
            } else {
                nodeOverrideSettingsBuilder.put("plugins.security.audit.type", "noop");
            }
            return this;
        }

        public List<TestSecurityConfig.User> getUsers() {
            return testSecurityConfig.getUsers();
        }

        public Builder roles(Role... roles) {
            testSecurityConfig.roles(roles);
            return this;
        }

        public Builder rolesMapping(TestSecurityConfig.RoleMapping... mappings) {
            testSecurityConfig.rolesMapping(mappings);
            return this;
        }

        public Builder authc(TestSecurityConfig.AuthcDomain authc) {
            testSecurityConfig.authc(authc);
            return this;
        }

        public Builder authz(AuthzDomain authzDomain) {
            testSecurityConfig.authz(authzDomain);
            return this;
        }

        public Builder clusterName(String clusterName) {
            this.clusterName = clusterName;
            return this;
        }

        public Builder configIndexName(String configIndexName) {
            testSecurityConfig.configIndexName(configIndexName);
            return this;
        }

        public Builder testCertificates(TestCertificates certificates) {
            this.testCertificates = certificates;
            return this;
        }

        public Builder anonymousAuth(boolean anonAuthEnabled) {
            testSecurityConfig.anonymousAuth(anonAuthEnabled);
            return this;
        }

        public Builder xff(XffConfig xffConfig) {
            testSecurityConfig.xff(xffConfig);
            return this;
        }

        public Builder onBehalfOf(OnBehalfOfConfig onBehalfOfConfig) {
            testSecurityConfig.onBehalfOf(onBehalfOfConfig);
            return this;
        }

        public Builder loadConfigurationIntoIndex(boolean loadConfigurationIntoIndex) {
            this.loadConfigurationIntoIndex = loadConfigurationIntoIndex;
            return this;
        }

        public Builder certificates(TestCertificates certificates) {
            this.testCertificates = certificates;
            return this;
        }

        public Builder doNotFailOnForbidden(boolean doNotFailOnForbidden) {
            testSecurityConfig.doNotFailOnForbidden(doNotFailOnForbidden);
            return this;
        }

        public Builder defaultConfigurationInitDirectory(String defaultConfigurationInitDirectory) {
            this.defaultConfigurationInitDirectory = defaultConfigurationInitDirectory;
            return this;
        }

        public LocalCluster build() {
            try {
                if (testCertificates == null) {
                    testCertificates = new TestCertificates(clusterManager.getNodes());
                }
                clusterName += "_" + num.incrementAndGet();
                Settings settings = nodeOverrideSettingsBuilder.build();
                return new LocalCluster(
                    clusterName,
                    testSecurityConfig,
                    sslOnly,
                    settings,
                    clusterManager,
                    plugins,
                    testCertificates,
                    clusterDependencies,
                    remoteClusters,
                    testIndices,
                    loadConfigurationIntoIndex,
                    defaultConfigurationInitDirectory
                );
            } catch (Exception e) {
                log.error("Failed to build LocalCluster", e);
                throw new RuntimeException(e);
            }
        }

    }

    @Override
    public TestCertificates getTestCertificates() {
        return testCertificates;
    }

}
