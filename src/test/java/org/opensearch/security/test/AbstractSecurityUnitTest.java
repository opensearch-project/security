/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

package org.opensearch.security.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope.Scope;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.message.BasicHeader;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.cluster.node.DiscoveryNodeRole;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.test.helper.cluster.ClusterHelper;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.test.helper.rules.SecurityTestWatcher;
import org.opensearch.threadpool.ThreadPool;

import io.netty.handler.ssl.OpenSsl;

/*
 * There are real thread leaks during test execution, not all threads are
 * properly waited on or interrupted.  While this normally doesn't create test
 * failures, retries mitigate this.  Remove this attribute to explore these
 * issues.
 */
@ThreadLeakScope(Scope.NONE)
public abstract class AbstractSecurityUnitTest extends RandomizedTest {

    private static final String NODE_ROLE_KEY = "node.roles";
    protected static final AtomicLong num = new AtomicLong();
    protected static boolean withRemoteCluster;

    static {
        final Logger log = LogManager.getLogger(AbstractSecurityUnitTest.class);

        log.info("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " " + System.getProperty("os.version"));
        log.info("Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        log.info(
            "JVM Impl.: "
                + System.getProperty("java.vm.version")
                + " "
                + System.getProperty("java.vm.vendor")
                + " "
                + System.getProperty("java.vm.name")
        );
        log.info("Open SSL available: " + OpenSsl.isAvailable());
        log.info("Open SSL version: " + OpenSsl.versionString());
        withRemoteCluster = Boolean.parseBoolean(System.getenv("TESTARG_unittests_with_remote_cluster"));
        log.info("With remote cluster: " + withRemoteCluster);
        // System.setProperty("security.display_lic_none","true");
    }

    protected final Logger log = LogManager.getLogger(this.getClass());
    public static final ThreadPool MOCK_POOL = new ThreadPool(Settings.builder().put("node.name", "mock").build());

    // TODO Test Matrix
    protected boolean allowOpenSSL = false; // disabled, we test this already in SSL Plugin
    // enable//disable enterprise modules
    // 1node and 3 node

    @Rule
    public TestName name = new TestName();

    @Rule
    public final TemporaryFolder repositoryPath = new TemporaryFolder();

    @Rule
    public final TestWatcher testWatcher = new SecurityTestWatcher();

    public static Header encodeBasicHeader(final String username, final String password) {
        return new BasicHeader(
            "Authorization",
            "Basic "
                + Base64.getEncoder().encodeToString((username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8))
        );
    }

    protected RestHighLevelClient getRestClient(ClusterInfo info, String keyStoreName, String trustStoreName) {
        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        try {
            SSLContextBuilder sslContextBuilder = SSLContexts.custom();
            File keyStoreFile = FileHelper.getAbsoluteFilePathFromClassPath(prefix + keyStoreName).toFile();
            KeyStore keyStore = KeyStore.getInstance(keyStoreName.endsWith(".jks") ? "JKS" : "PKCS12");
            keyStore.load(new FileInputStream(keyStoreFile), null);
            sslContextBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray());

            KeyStore trustStore = KeyStore.getInstance(trustStoreName.endsWith(".jks") ? "JKS" : "PKCS12");
            File trustStoreFile = FileHelper.getAbsoluteFilePathFromClassPath(prefix + trustStoreName).toFile();
            trustStore.load(new FileInputStream(trustStoreFile), "changeit".toCharArray());

            sslContextBuilder.loadTrustMaterial(trustStore, null);
            SSLContext sslContext = sslContextBuilder.build();

            HttpHost httpHost = new HttpHost(info.httpHost, info.httpPort, "https");

            RestClientBuilder restClientBuilder = RestClient.builder(httpHost)
                .setHttpClientConfigCallback(
                    builder -> builder.setSSLStrategy(
                        new SSLIOSessionStrategy(
                            sslContext,
                            new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3" },
                            null,
                            NoopHostnameVerifier.INSTANCE
                        )
                    )
                );
            return new RestHighLevelClient(restClientBuilder);
        } catch (Exception e) {
            log.error("Cannot create client", e);
            throw new RuntimeException("Cannot create client", e);
        }
    }

    /** Wait for the security plugin to load roles. */
    public void waitForInit(Client client) {
        int maxRetries = 5;
        Optional<Exception> retainedException = Optional.empty();
        for (int i = 0; i < maxRetries; i++) {
            try {
                client.admin().cluster().health(new ClusterHealthRequest()).actionGet();
                retainedException = Optional.empty();
                return;
            } catch (OpenSearchSecurityException ex) {
                if (ex.getMessage().contains("OpenSearch Security not initialized")) {
                    retainedException = Optional.of(ex);
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) { /* ignored */ }
                } else {
                    // plugin is initialized, but another error received.
                    // Example could be user does not have permissions for cluster:monitor/health
                    retainedException = Optional.empty();
                }
            }
        }
        if (retainedException.isPresent()) {
            throw new RuntimeException(retainedException.get());
        }
    }

    public static Settings.Builder nodeRolesSettings(
        final Settings.Builder settingsBuilder,
        final boolean isClusterManager,
        final boolean isDataNode
    ) {
        final ImmutableList.Builder<String> nodeRolesBuilder = ImmutableList.<String>builder();
        if (isDataNode) {
            nodeRolesBuilder.add(DiscoveryNodeRole.DATA_ROLE.roleName());
        }
        if (isClusterManager) {
            nodeRolesBuilder.add(DiscoveryNodeRole.CLUSTER_MANAGER_ROLE.roleName());
        }

        final Settings nodeRoleSettings = Settings.builder().putList(NODE_ROLE_KEY, nodeRolesBuilder.build()).build();
        return mergeNodeRolesAndSettings(settingsBuilder, nodeRoleSettings);
    }

    public static Settings.Builder mergeNodeRolesAndSettings(final Settings.Builder settingsBuilder, final Settings otherSettings) {
        final ImmutableSet.Builder<String> originalRoles = ImmutableSet.<String>builder()
            .addAll(settingsBuilder.build().getAsList(NODE_ROLE_KEY, ImmutableList.<String>of()))
            .addAll(otherSettings.getAsList(NODE_ROLE_KEY, ImmutableList.<String>of()));

        return settingsBuilder.put(otherSettings).putList(NODE_ROLE_KEY, originalRoles.build().asList());
    }

    protected void initialize(ClusterHelper clusterHelper, ClusterInfo clusterInfo, DynamicSecurityConfig securityConfig)
        throws IOException {
        try (Client tc = clusterHelper.nodeClient()) {
            Assert.assertEquals(clusterInfo.numNodes, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            try {
                tc.admin().indices().create(new CreateIndexRequest(".opendistro_security")).actionGet();
            } catch (Exception e) {
                // ignore
            }

            List<IndexRequest> indexRequests = securityConfig.getDynamicConfig(getResourceFolder());
            for (IndexRequest ir : indexRequests) {
                tc.index(ir).actionGet();
            }

            ConfigUpdateResponse cur = tc.execute(
                ConfigUpdateAction.INSTANCE,
                new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0]))
            ).actionGet();
            Assert.assertFalse(cur.failures().toString(), cur.hasFailures());
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());

            SearchResponse sr = tc.search(new SearchRequest(".opendistro_security")).actionGet();
            sr = tc.search(new SearchRequest(".opendistro_security")).actionGet();
        }
    }

    protected Settings.Builder minimumSecuritySettingsBuilder(int node, boolean sslOnly, Settings other) {

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        Settings.Builder builder = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL);

        // If custom transport settings are not defined use defaults
        if (!hasCustomTransportSettings(other)) {
            builder.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                    FileHelper.getAbsoluteFilePathFromClassPath(prefix + "node-0-keystore.jks")
                )
                .put(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                    FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")
                )
                .put("plugins.security.ssl.transport.enforce_hostname_verification", false);
        }

        if (!sslOnly) {
            builder.putList("plugins.security.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De");
            builder.put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false);
        }
        builder.put("cluster.routing.allocation.disk.threshold_enabled", false);
        builder.put(other);
        return builder;
    }

    protected NodeSettingsSupplier minimumSecuritySettings(Settings other) {
        return new NodeSettingsSupplier() {
            @Override
            public Settings get(int i) {
                return minimumSecuritySettingsBuilder(i, false, other).build();
            }
        };
    }

    protected NodeSettingsSupplier minimumSecuritySettingsSslOnly(Settings other) {

        return new NodeSettingsSupplier() {
            @Override
            public Settings get(int i) {
                return minimumSecuritySettingsBuilder(i, true, other).build();
            }
        };
    }

    protected NodeSettingsSupplier minimumSecuritySettingsSslOnlyWithOneNodeNonSSL(Settings other, int nonSSLNodeNum) {

        return new NodeSettingsSupplier() {
            @Override
            public Settings get(int i) {
                if (i == nonSSLNodeNum) {
                    return Settings.builder().build();
                }
                return minimumSecuritySettingsBuilder(i, true, other).build();
            }
        };
    }

    protected NodeSettingsSupplier genericMinimumSecuritySettings(List<Settings> others, List<Boolean> sslOnly) {

        return i -> {
            assert i > 0; // i is 1-indexed

            // Set to default if input does not have value at (i-1) index
            boolean sslOnlyFlag = i > sslOnly.size() ? false : sslOnly.get(i - 1);
            Settings settings = i > others.size() ? Settings.EMPTY : others.get(i - 1);

            return minimumSecuritySettingsBuilder(i, sslOnlyFlag, settings).build();
        };
    }

    protected void initialize(ClusterHelper clusterHelper, ClusterInfo info) throws IOException {
        initialize(clusterHelper, info, new DynamicSecurityConfig());
    }

    protected final void assertContains(HttpResponse res, String pattern) {
        Assert.assertTrue(WildcardMatcher.from(pattern).test(res.getBody()));
    }

    protected final void assertNotContains(HttpResponse res, String pattern) {
        Assert.assertFalse(WildcardMatcher.from(pattern).test(res.getBody()));
    }

    protected String getResourceFolder() {
        return null;
    }

    /**
     * Check if transport certs are is mentioned in the custom settings
     * @param customSettings custom settings from the test class
     * @return boolean flag indicating if transport settings are defined
     */
    protected boolean hasCustomTransportSettings(Settings customSettings) {
        // If Transport key extended usage is enabled this is true
        return Boolean.parseBoolean(customSettings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED))
            || customSettings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH) != null;
    }
}
