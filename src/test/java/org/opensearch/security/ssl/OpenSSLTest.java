/*
 * Copyright 2015-2017 floragunn GmbH
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

package org.opensearch.security.ssl;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import io.netty.handler.ssl.OpenSsl;
import io.netty.util.internal.PlatformDependent;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.transport.Netty4ModulePlugin;

public class OpenSSLTest extends SSLTest {
    private static final String USE_NETTY_DEFAULT_ALLOCATOR_PROPERTY = "opensearch.unsafe.use_netty_default_allocator";
    private static String USE_NETTY_DEFAULT_ALLOCATOR;

    @BeforeClass
    public static void enableNettyDefaultAllocator() {
        USE_NETTY_DEFAULT_ALLOCATOR = System.getProperty(USE_NETTY_DEFAULT_ALLOCATOR_PROPERTY);
        System.setProperty(USE_NETTY_DEFAULT_ALLOCATOR_PROPERTY, "true");
    }

    @AfterClass
    public static void restoreNettyDefaultAllocator() {
        if (USE_NETTY_DEFAULT_ALLOCATOR != null) {
            System.setProperty(USE_NETTY_DEFAULT_ALLOCATOR_PROPERTY, USE_NETTY_DEFAULT_ALLOCATOR);
        } else {
            System.clearProperty(USE_NETTY_DEFAULT_ALLOCATOR_PROPERTY);
        }
    }

    @Before
    public void setup() {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        allowOpenSSL = true;
    }

    @Test
    public void testAvailCiphersOpenSSL() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());

        // Set<String> openSSLAvailCiphers = new
        // HashSet<>(OpenSsl.availableCipherSuites());
        // System.out.println("OpenSSL available ciphers: "+openSSLAvailCiphers);
        // ECDHE-RSA-AES256-SHA, ECDH-ECDSA-AES256-SHA, DH-DSS-DES-CBC-SHA,
        // ADH-AES256-SHA256, ADH-CAMELLIA128-SHA

        final Set<String> openSSLSecureCiphers = new HashSet<>();
        for (final String secure : SSLConfigConstants.getSecureSSLCiphers(Settings.EMPTY, false)) {
            if (OpenSsl.isCipherSuiteAvailable(secure)) {
                openSSLSecureCiphers.add(secure);
            }
        }

        System.out.println("OpenSSL secure ciphers: " + openSSLSecureCiphers);
        Assert.assertTrue(openSSLSecureCiphers.size() > 0);
    }
    
    @Test
    public void testNodeClientSSLwithOpenSslTLSv13() throws Exception {
        
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable() && OpenSsl.version() > 0x10101009L);

        final Settings settings = Settings.builder().put("plugins.security.ssl.transport.enabled", true)
                .put(ConfigConstants.SECURITY_SSL_ONLY, true)
                .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("plugins.security.ssl.transport.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks"))
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks"))
                .put("plugins.security.ssl.transport.enforce_hostname_verification", false)
                .put("plugins.security.ssl.transport.resolve_hostname", false)
                .putList(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, "TLSv1.3")
                .putList(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, "TLS_CHACHA20_POLY1305_SHA256")
                .put("node.max_local_storage_nodes",4)
                .build();

        setupSslOnlyMode(settings);
        
        RestHelper rh = nonSslRestHelper();

        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false) 
                .put("cluster.name", clusterInfo.clustername).put("path.home", "/tmp")
                .put("node.name", "client_node_" + new Random().nextInt())
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/ssl/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/ssl/logs")
                .put("path.home", "./target")
                .put("discovery.initial_state_timeout","8s")
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost+":"+clusterInfo.nodePort)
                .put(settings)// -----
                .build();

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4ModulePlugin.class, OpenSearchSecurityPlugin.class).start()) {
            ClusterHealthResponse res = node.client().admin().cluster().health(new ClusterHealthRequest().waitForNodes("4").timeout(TimeValue.timeValueSeconds(5))).actionGet();
            Assert.assertFalse(res.isTimedOut());
            Assert.assertEquals(4, res.getNumberOfNodes());
            Assert.assertEquals(4, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
        }

        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_count\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_count\" : 0"));
    }
}
