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

import org.opensearch.security.OpenSearchSecurityPlugin;
import io.netty.util.internal.PlatformDependent;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.transport.Netty4Plugin;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import io.netty.handler.ssl.OpenSsl;

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
        allowOpenSSL = true;
    }

    @Test
    public void testEnsureOpenSSLAvailability() {
        //Assert.assertTrue("OpenSSL not available: "+String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
                
        final String openSSLOptional = System.getenv("OPENDISTRO_SECURITY_TEST_OPENSSL_OPT");
        System.out.println("OPENDISTRO_SECURITY_TEST_OPENSSL_OPT "+openSSLOptional);
        if(!Boolean.parseBoolean(openSSLOptional)) {
            System.out.println("OpenSSL must be available");
            Assert.assertTrue("OpenSSL not available: "+String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
        } else {
            System.out.println("OpenSSL can be available");
        }
    }

    @Override
    @Test
    public void testHttps() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttps();
    }

    @Override
    @Test
    public void testHttpsAndNodeSSL() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsAndNodeSSL();
    }

    @Override
    @Test
    public void testHttpPlainFail() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpPlainFail();
    }

    @Override
    @Test
    public void testHttpsNoEnforce() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsNoEnforce();
    }

    @Override
    @Test
    public void testHttpsV3Fail() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsV3Fail();
    }

    @Override
    @Test(timeout=40000)
    public void testTransportClientSSL() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testTransportClientSSL();
    }

    @Override
    @Test(timeout=40000)
    public void testNodeClientSSL() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testNodeClientSSL();
    }

    @Override
    @Test(timeout=40000)
    public void testTransportClientSSLFail() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testTransportClientSSLFail();
    }
    
    @Override
    @Test
    public void testHttpsOptionalAuth() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsOptionalAuth();
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
    public void testHttpsEnforceFail() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsEnforceFail();
    }

    @Override
    public void testCipherAndProtocols() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testCipherAndProtocols();
    }

    @Override
    public void testHttpsAndNodeSSLFailedCipher() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsAndNodeSSLFailedCipher();
    }
    
    @Test
    public void testHttpsAndNodeSSLPem() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsAndNodeSSLPem();
    }
    
    @Test
    public void testHttpsAndNodeSSLPemEnc() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testHttpsAndNodeSSLPemEnc();
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

        final Settings tcSettings = Settings.builder().put("cluster.name", clusterInfo.clustername).put("path.home", "/tmp")
                .put("node.name", "client_node_" + new Random().nextInt())
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/ssl/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/ssl/logs")
                .put("path.home", "./target")
                .put("discovery.initial_state_timeout","8s")
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost+":"+clusterInfo.nodePort)
                .put(settings)// -----
                .build();

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class).start()) {
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

    @Test
    public void testTLSv1() throws Exception {
        Assume.assumeTrue(OpenSearchSecuritySSLPlugin.OPENSSL_SUPPORTED && OpenSsl.isAvailable());
        super.testTLSv1();
    }

    @Test
    public void testJava12WithOpenSslEnabled() throws Exception {
        // If the user has Java 12 running and OpenSSL enabled, we give
        // a warning, ignore OpenSSL and use JDK SSl instead.
        Assume.assumeTrue(PlatformDependent.javaVersion() >= 12);
        super.testHttps();
    }
}
