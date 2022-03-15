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
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.test;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterators;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.client.*;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.OpenSearchSecurityPlugin;
import io.netty.handler.ssl.OpenSsl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.test.helper.cluster.ClusterHelper;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.plugins.Plugin;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.test.helper.rules.SecurityTestWatcher;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Netty4Plugin;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;

import org.opensearch.security.securityconf.impl.CType;

import javax.net.ssl.SSLContext;

public abstract class AbstractSecurityUnitTest {

    protected static final AtomicLong num = new AtomicLong();
    protected static boolean withRemoteCluster;

    static {

        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println(
                "Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " "
                + System.getProperty("java.vm.vendor") + " " + System.getProperty("java.vm.name"));
        System.out.println("Open SSL available: " + OpenSsl.isAvailable());
        System.out.println("Open SSL version: " + OpenSsl.versionString());
        withRemoteCluster = Boolean.parseBoolean(System.getenv("TESTARG_unittests_with_remote_cluster"));
        System.out.println("With remote cluster: " + withRemoteCluster);
        //System.setProperty("security.display_lic_none","true");
    }

    protected final Logger log = LoggerFactory.getLogger(this.getClass());
    public static final ThreadPool MOCK_POOL = new ThreadPool(Settings.builder().put("node.name",  "mock").build());

    //TODO Test Matrix
    protected boolean allowOpenSSL = false; //disabled, we test this already in SSL Plugin
    //enable//disable enterprise modules
    //1node and 3 node

    @Rule
    public TestName name = new TestName();

    @Rule
    public final TemporaryFolder repositoryPath = new TemporaryFolder();

	@Rule
	public final TestWatcher testWatcher = new SecurityTestWatcher();

    public static Header encodeBasicHeader(final String username, final String password) {
        return new BasicHeader("Authorization", "Basic "+Base64.getEncoder().encodeToString(
                (username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8)));
    }

    protected RestHighLevelClient getRestClient(ClusterInfo info, String keyStoreName, String trustStoreName) {
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

        try {
            SSLContextBuilder sslContextBuilder = SSLContexts.custom();
            File keyStoreFile = FileHelper.getAbsoluteFilePathFromClassPath(prefix + keyStoreName).toFile();
            KeyStore keyStore = KeyStore.getInstance(keyStoreName.endsWith(".jks")?"JKS":"PKCS12");
            keyStore.load(new FileInputStream(keyStoreFile), null);
            sslContextBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray());

            KeyStore trustStore = KeyStore.getInstance(trustStoreName.endsWith(".jks")?"JKS":"PKCS12");
            File trustStoreFile = FileHelper.getAbsoluteFilePathFromClassPath(prefix + trustStoreName).toFile();
            trustStore.load(new FileInputStream(trustStoreFile),
                    "changeit".toCharArray());

            sslContextBuilder.loadTrustMaterial(trustStore, null);
            SSLContext sslContext = sslContextBuilder.build();

            HttpHost httpHost = new HttpHost(info.httpHost, info.httpPort, "https");

            RestClientBuilder restClientBuilder = RestClient.builder(httpHost)
                    .setHttpClientConfigCallback(
                            builder -> builder.setSSLStrategy(
                                    new SSLIOSessionStrategy(sslContext,
                                            new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3"},
                                            null,
                                            NoopHostnameVerifier.INSTANCE)));
            return new RestHighLevelClient(restClientBuilder);
        } catch (Exception e) {
            log.error("Cannot create client", e);
            throw new RuntimeException("Cannot create client", e);
        }
    }

    protected void initialize(ClusterHelper clusterHelper, ClusterInfo clusterInfo, DynamicSecurityConfig securityConfig) throws IOException {
        try (Client tc = clusterHelper.nodeClient()) {
            Assert.assertEquals(clusterInfo.numNodes,
                    tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());

            try {
                tc.admin().indices().create(new CreateIndexRequest(".opendistro_security")).actionGet();
            } catch (Exception e) {
                //ignore
            }

            List<IndexRequest> indexRequests = securityConfig.getDynamicConfig(getResourceFolder());
            for(IndexRequest ir: indexRequests) {
                tc.index(ir).actionGet();
            }

            ConfigUpdateResponse cur = tc
                    .execute(ConfigUpdateAction.INSTANCE, new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0])))
                    .actionGet();
            Assert.assertFalse(cur.failures().toString(), cur.hasFailures());
            Assert.assertEquals(clusterInfo.numNodes, cur.getNodes().size());

            SearchResponse sr = tc.search(new SearchRequest(".opendistro_security")).actionGet();
            //Assert.assertEquals(5L, sr.getHits().getTotalHits());

            sr = tc.search(new SearchRequest(".opendistro_security")).actionGet();
            //Assert.assertEquals(5L, sr.getHits().getTotalHits());

            String type=securityConfig.getType();
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }
    }

    protected Settings.Builder minimumSecuritySettingsBuilder(int node, boolean sslOnly, Settings other) {

        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

        Settings.Builder builder = Settings.builder()
                .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL);

        // If custom transport settings are not defined use defaults
        if (!hasCustomTransportSettings(other)) {
            builder.put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                    FileHelper.getAbsoluteFilePathFromClassPath(prefix+"node-0-keystore.jks"))
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks"))
                .put("plugins.security.ssl.transport.enforce_hostname_verification", false);
        }

        if(!sslOnly) {
            builder.putList("plugins.security.authcz.admin_dn", "CN=kirk,OU=client,O=client,l=tEst, C=De");
            builder.put(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, false);
        }

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
            boolean sslOnlyFlag = i > sslOnly.size() ? false : sslOnly.get(i-1);
            Settings settings = i > others.size() ? Settings.EMPTY : others.get(i-1);

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


    protected String getType() {
        return "_doc";
    }

    /**
     * Check if transport certs are is mentioned in the custom settings
     * @param customSettings custom settings from the test class
     * @return boolean flag indicating if transport settings are defined
     */
    protected boolean hasCustomTransportSettings(Settings customSettings) {
        // If Transport key extended usage is enabled this is true
        return Boolean.parseBoolean(customSettings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED))  ||
                customSettings.get(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH) != null;
    }
}
