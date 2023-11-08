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

import java.net.SocketException;
import java.nio.file.Paths;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import com.google.common.collect.Lists;
import org.apache.http.NoHttpResponseException;
import org.apache.lucene.util.Constants;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.transport.Netty4Plugin;

import io.netty.util.internal.PlatformDependent;

import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_PEMKEY_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD;

@SuppressWarnings({ "resource", "unchecked" })
public class SSLTest extends SingleClusterTest {

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    protected boolean allowOpenSSL = false;

    @Test
    public void testHttps() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .putList(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, "TLSv1.1", "TLSv1.2")
            .putList(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            .putList(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, "TLSv1.1", "TLSv1.2")
            .putList(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "node-untspec5-keystore.p12";

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty&show_dn=true");
        Assert.assertTrue(res.contains("EMAILADDRESS=unt@tst.com"));
        Assert.assertTrue(res.contains("local_certificates_list"));
        Assert.assertFalse(
            rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty&show_dn=false").contains("local_certificates_list")
        );
        Assert.assertFalse(rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("local_certificates_list"));

        res = rh.executeSimpleRequest("_nodes/settings?pretty");
        Assert.assertTrue(res.contains(clusterInfo.clustername));
        Assert.assertFalse(res.contains("\"opendistro_security\""));
        Assert.assertFalse(res.contains("keystore_filepath"));
        // Assert.assertTrue(rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));

    }

    @Test
    public void testCipherAndProtocols() throws Exception {

        Security.setProperty("jdk.tls.disabledAlgorithms", "");

        Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            // WEAK and insecure cipher, do NOT use this, its here for unittesting only!!!
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS, "SSL_RSA_EXPORT_WITH_RC4_40_MD5")
            // WEAK and insecure protocol, do NOT use this, its here for unittesting only!!!
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, "SSLv3")
            .put("client.type", "node")
            .put("path.home", ".")
            .build();

        try {
            String[] enabledCiphers = new DefaultSecurityKeyStore(settings, Paths.get(".")).createHTTPSSLEngine().getEnabledCipherSuites();
            String[] enabledProtocols = new DefaultSecurityKeyStore(settings, Paths.get(".")).createHTTPSSLEngine().getEnabledProtocols();

            if (allowOpenSSL) {
                Assert.assertEquals(2, enabledProtocols.length); // SSLv2Hello is always enabled when using openssl
                Assert.assertTrue("Check SSLv3", "SSLv3".equals(enabledProtocols[0]) || "SSLv3".equals(enabledProtocols[1]));
                Assert.assertEquals(1, enabledCiphers.length);
                Assert.assertEquals("TLS_RSA_EXPORT_WITH_RC4_40_MD5", enabledCiphers[0]);
            } else {
                Assert.assertEquals(1, enabledProtocols.length);
                Assert.assertEquals("SSLv3", enabledProtocols[0]);
                Assert.assertEquals(1, enabledCiphers.length);
                Assert.assertEquals("SSL_RSA_EXPORT_WITH_RC4_40_MD5", enabledCiphers[0]);
            }

            settings = Settings.builder()
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
                .put(ConfigConstants.SECURITY_SSL_ONLY, true)
                .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                    FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
                )
                .put(
                    SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                    FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
                )
                // WEAK and insecure cipher, do NOT use this, its here for unittesting only!!!
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, "SSL_RSA_EXPORT_WITH_RC4_40_MD5")
                // WEAK and insecure protocol, do NOT use this, its here for unittesting only!!!
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, "SSLv3")
                .put("client.type", "node")
                .put("path.home", ".")
                .build();

            enabledCiphers = new DefaultSecurityKeyStore(settings, Paths.get(".")).createServerTransportSSLEngine()
                .getEnabledCipherSuites();
            enabledProtocols = new DefaultSecurityKeyStore(settings, Paths.get(".")).createServerTransportSSLEngine().getEnabledProtocols();

            if (allowOpenSSL) {
                Assert.assertEquals(2, enabledProtocols.length); // SSLv2Hello is always enabled when using openssl
                Assert.assertTrue("Check SSLv3", "SSLv3".equals(enabledProtocols[0]) || "SSLv3".equals(enabledProtocols[1]));
                Assert.assertEquals(1, enabledCiphers.length);
                Assert.assertEquals("TLS_RSA_EXPORT_WITH_RC4_40_MD5", enabledCiphers[0]);
            } else {
                Assert.assertEquals(1, enabledProtocols.length);
                Assert.assertEquals("SSLv3", enabledProtocols[0]);
                Assert.assertEquals(1, enabledCiphers.length);
                Assert.assertEquals("SSL_RSA_EXPORT_WITH_RC4_40_MD5", enabledCiphers[0]);
            }
            enabledCiphers = new DefaultSecurityKeyStore(settings, Paths.get(".")).createClientTransportSSLEngine(null, -1)
                .getEnabledCipherSuites();
            enabledProtocols = new DefaultSecurityKeyStore(settings, Paths.get(".")).createClientTransportSSLEngine(null, -1)
                .getEnabledProtocols();

            if (allowOpenSSL) {
                Assert.assertEquals(2, enabledProtocols.length); // SSLv2Hello is always enabled when using openssl
                Assert.assertTrue("Check SSLv3", "SSLv3".equals(enabledProtocols[0]) || "SSLv3".equals(enabledProtocols[1]));
                Assert.assertEquals(1, enabledCiphers.length);
                Assert.assertEquals("TLS_RSA_EXPORT_WITH_RC4_40_MD5", enabledCiphers[0]);
            } else {
                Assert.assertEquals(1, enabledProtocols.length);
                Assert.assertEquals("SSLv3", enabledProtocols[0]);
                Assert.assertEquals(1, enabledCiphers.length);
                Assert.assertEquals("SSL_RSA_EXPORT_WITH_RC4_40_MD5", enabledCiphers[0]);
            }
        } catch (OpenSearchSecurityException e) {
            Assert.assertTrue(
                "Check if error contains 'no valid cipher suites' -> " + e.toString(),
                e.toString().contains("no valid cipher suites")
                    || e.toString().contains("failed to set cipher suite")
                    || e.toString().contains("Unable to configure permitted SSL ciphers")
                    || e.toString().contains("OPENSSL_internal:NO_CIPHER_MATCH")
            );
            Assert.assertTrue("Check if >= Java 8 and no openssl", allowOpenSSL ? true : Constants.JRE_IS_MINIMUM_JAVA8);
        }
    }

    @Test
    public void testHttpsOptionalAuth() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));

        res = rh.executeSimpleRequest("_nodes/settings?pretty");
        Assert.assertTrue(res.contains(clusterInfo.clustername));
        Assert.assertFalse(res.contains("\"opendistro_security\""));
    }

    @Test
    public void testHttpsAndNodeSSL() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )

            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
        String res2 = rh.executeSimpleRequest("_nodes/settings?pretty");
        Assert.assertTrue(res2.contains(clusterInfo.clustername));
        Assert.assertFalse(res2.contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(res2.contains("\"rx_count\" : 0"));
        Assert.assertFalse(res2.contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(res2.contains("\"tx_count\" : 0"));

    }

    @Test
    public void testHttpsAndNodeSSLPKCS8Pem() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem"))
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));
        // Assert.assertTrue(!executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("null"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
    }

    @Test
    public void testHttpsAndNodeSSLPKCS1Pem() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-pkcs1.key.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-pkcs1.key.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));
    }

    @Test
    public void testHttpsAndNodeSSLPemEnc() throws Exception {
        final MockSecureSettings mockSecureSettings = new MockSecureSettings();
        mockSecureSettings.setString(SECURITY_SSL_HTTP_PEMKEY_PASSWORD.propertyName, "changeit");
        mockSecureSettings.setString(SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD.propertyName, "changeit");

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.crt.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.key")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.crt.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.key"))
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .setSecureSettings(mockSecureSettings)
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));
        // Assert.assertTrue(!executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("null"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
    }

    @Test
    public void testSSLPemEncWithInsecureSettings() throws Exception {
        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.crt.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.key")
            )
            // legacy insecure passwords
            .put(SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD.insecurePropertyName, "changeit")
            .put(SECURITY_SSL_HTTP_PEMKEY_PASSWORD.insecurePropertyName, "changeit")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.crt.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/pem/node-4.key"))
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        Assert.assertTrue(
            rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE")
        );
    }

    @Test
    public void testHttpsAndNodeSSLFailedCipher() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS, "INVALID_CIPHER")

            .build();

        try {
            setupSslOnlyMode(settings);
            Assert.fail();
        } catch (Exception e1) {
            Throwable e = ExceptionUtils.getRootCause(e1);
            Assert.assertTrue(e.toString(), e.toString().contains("no valid cipher"));
        }
    }

    @Test
    public void testHttpPlainFail() throws Exception {
        thrown.expect(NoHttpResponseException.class);

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "OPTIONAL")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = false;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = false;

        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));
        Assert.assertTrue(
            rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE")
        );
    }

    @Test
    public void testHttpsNoEnforce() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "NONE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = false;

        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));
        Assert.assertFalse(
            rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE")
        );
    }

    @Test
    public void testHttpsEnforceFail() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = false;

        try {
            rh.executeSimpleRequest("");
            Assert.fail();
        } catch (SocketException | SSLException e) {
            // expected
        } catch (Exception e) {
            Assert.fail("Unexpected exception " + e);
        }
    }

    @Test
    public void testHttpsV3Fail() throws Exception {
        thrown.expect(SSLHandshakeException.class);

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "NONE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = false;
        rh.enableHTTPClientSSLv3Only = true;

        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));
    }

    @Test
    public void testNodeClientSSL() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = nonSslRestHelper();

        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false)
            .put("cluster.name", clusterInfo.clustername)
            .put("path.home", ".")
            .put("node.name", "client_node_" + new Random().nextInt())
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/ssl/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/ssl/logs")
            .put("path.home", "./target")
            .put("discovery.initial_state_timeout", "8s")
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .put(settings)// -----
            .build();

        try (
            Node node = new PluginAwareNode(false, tcSettings, Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class))
                .start()
        ) {
            ClusterHealthResponse res = node.client()
                .admin()
                .cluster()
                .health(new ClusterHealthRequest().waitForNodes("4").timeout(TimeValue.timeValueSeconds(15)))
                .actionGet();
            Assert.assertFalse(res.isTimedOut());
            Assert.assertEquals(4, res.getNumberOfNodes());
            Assert.assertEquals(4, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
        }

        String res = rh.executeSimpleRequest("_nodes/stats?pretty");

        Assert.assertFalse(res.contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"rx_count\" : 0"));
        Assert.assertFalse(res.contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"tx_count\" : 0"));
    }

    @Test
    public void testAvailCiphers() throws Exception {
        final SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(null, null, null);
        final SSLEngine engine = serverContext.createSSLEngine();
        final List<String> jdkSupportedCiphers = new ArrayList<>(Arrays.asList(engine.getSupportedCipherSuites()));
        jdkSupportedCiphers.retainAll(SSLConfigConstants.getSecureSSLCiphers(Settings.EMPTY, false));
        engine.setEnabledCipherSuites(jdkSupportedCiphers.toArray(new String[0]));

        final List<String> jdkEnabledCiphers = Arrays.asList(engine.getEnabledCipherSuites());
        // example
        // TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        // TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        Assert.assertTrue(jdkEnabledCiphers.size() > 0);
    }

    @Test
    public void testUnmodifieableCipherProtocolConfig() throws Exception {
        SSLConfigConstants.getSecureSSLProtocols(Settings.EMPTY, false)[0] = "bogus";
        Assert.assertEquals("TLSv1.3", SSLConfigConstants.getSecureSSLProtocols(Settings.EMPTY, false)[0]);

        try {
            SSLConfigConstants.getSecureSSLCiphers(Settings.EMPTY, false).set(0, "bogus");
            Assert.fail();
        } catch (UnsupportedOperationException e) {
            // expected
        }
    }

    @Test
    public void testCustomPrincipalExtractor() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, "org.opensearch.security.ssl.TestPrincipalExtractor")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        log.debug("OpenSearch started");

        final Settings tcSettings = Settings.builder()
            .put("cluster.name", clusterInfo.clustername)
            .put("path.home", ".")
            .put(settings)
            .build();

        try (Client tc = getClient()) {

            log.debug("Client built, connect now to {}:{}", clusterInfo.nodeHost, clusterInfo.httpPort);

            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            log.debug("Client connected");
            TestPrincipalExtractor.reset();
            Assert.assertEquals(
                "test",
                tc.index(new IndexRequest("test").setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{\"a\":5}", XContentType.JSON))
                    .actionGet()
                    .getIndex()
            );
            log.debug("Index created");
            Assert.assertEquals(1L, tc.search(new SearchRequest("test")).actionGet().getHits().getTotalHits().value);
            log.debug("Search done");
            Assert.assertEquals(3, tc.admin().cluster().health(new ClusterHealthRequest("test")).actionGet().getNumberOfNodes());
            log.debug("ClusterHealth done");
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
            log.debug("NodesInfoRequest asserted");
        }

        rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");

        // we need to test this in SG itself because in the SSL only plugin the info is not longer propagated
        // Assert.assertTrue(TestPrincipalExtractor.getTransportCount() > 0);
        Assert.assertTrue(TestPrincipalExtractor.getHttpCount() > 0);
    }

    @Test
    public void testCRLPem() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem"))
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/chain-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, CertificateValidatorTest.CRL_DATE.getTime())
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        Assert.assertTrue(rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("TLS"));
    }

    @Test
    public void testCRL() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, false)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, true)
            .put(SSLConfigConstants.SSECURITY_SSL_HTTP_CRL_FILE, FileHelper.getAbsoluteFilePathFromClassPath("ssl/crl/revoked.crl"))
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, CertificateValidatorTest.CRL_DATE.getTime())
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));

    }

    @Test
    public void testNodeClientSSLwithJavaTLSv13() throws Exception {

        // Java TLS 1.3 is available since Java 11
        Assume.assumeTrue(!allowOpenSSL && PlatformDependent.javaVersion() >= 11);

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .putList(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS, "TLSv1.3")
            .putList(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS, "TLS_AES_128_GCM_SHA256")
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = nonSslRestHelper();

        final Settings tcSettings = Settings.builder()
            .put("cluster.name", clusterInfo.clustername)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/ssl/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/ssl/logs")
            .put("path.home", "./target")
            .put("node.name", "client_node_" + new Random().nextInt())
            .put("discovery.initial_state_timeout", "8s")
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .put(settings)// -----
            .build();

        try (
            Node node = new PluginAwareNode(false, tcSettings, Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class))
                .start()
        ) {
            ClusterHealthResponse res = node.client()
                .admin()
                .cluster()
                .health(new ClusterHealthRequest().waitForNodes("4").timeout(TimeValue.timeValueSeconds(5)))
                .actionGet();
            Assert.assertFalse(res.isTimedOut());
            Assert.assertEquals(4, res.getNumberOfNodes());
            Assert.assertEquals(4, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().size());
        }

        String res = rh.executeSimpleRequest("_nodes/stats?pretty");
        Assert.assertFalse(res.contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"rx_count\" : 0"));
        Assert.assertFalse(res.contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"tx_count\" : 0"));
    }

    @Test
    public void testTLSv12() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS, "TLSv1.2")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;

        Assert.assertTrue(rh.executeSimpleRequest("_nodes/stats?pretty").contains("\"tx_size_in_bytes\""));
    }

    @Test
    public void testHttpsAndNodeSSLKeyPass() throws Exception {
        final MockSecureSettings mockSecureSettings = new MockSecureSettings();
        mockSecureSettings.setString(SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD.propertyName, "changeit");
        mockSecureSettings.setString(SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD.propertyName, "changeit");

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .setSecureSettings(mockSecureSettings)
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));

        res = rh.executeSimpleRequest("_nodes/stats?pretty");
        Assert.assertTrue(res.contains(clusterInfo.clustername));
        Assert.assertFalse(res.contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"rx_count\" : 0"));
        Assert.assertFalse(res.contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"tx_count\" : 0"));

    }

    @Test
    public void testHttpsAndNodeSSLKeyStoreExtendedUsageEnabled() throws Exception {
        final MockSecureSettings mockSecureSettings = new MockSecureSettings();
        mockSecureSettings.setString(SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD.propertyName, "changeit");
        mockSecureSettings.setString(SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD.propertyName, "changeit");
        mockSecureSettings.setString(SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD.propertyName, "changeit");

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)

            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS, "node-0-client")
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS, "node-0-server")
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS, "root-ca")
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS, "root-ca")

            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/truststore.jks")
            )

            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .setSecureSettings(mockSecureSettings)

            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));

        res = rh.executeSimpleRequest("_nodes/settings?pretty");
        Assert.assertTrue(res.contains(clusterInfo.clustername));
        Assert.assertFalse(res.contains("\"tx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"rx_count\" : 0"));
        Assert.assertFalse(res.contains("\"rx_size_in_bytes\" : 0"));
        Assert.assertFalse(res.contains("\"tx_count\" : 0"));

    }

    @Test(expected = IllegalStateException.class)
    public void testHttpsAndNodeSSLKeyPassFail() throws Exception {
        final MockSecureSettings mockSecureSettings = new MockSecureSettings();
        mockSecureSettings.setString(SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD.propertyName, "wrongpass");
        mockSecureSettings.setString(SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD.propertyName, "wrongpass");

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0-keystore.jks")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/truststore.jks")
            )
            .setSecureSettings(mockSecureSettings)
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        Assert.assertTrue(rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty").contains("TLS"));

    }

    @Test
    public void testHttpsAndNodeSSLPemExtendedUsageEnabled() throws Exception {

        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(ConfigConstants.SECURITY_SSL_ONLY, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED, true)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-client.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-key-client.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/root-ca.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-server.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/node-key-server.pem")
            )
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/extended_key_usage/root-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)

            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem"))
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem")
            )
            .build();

        setupSslOnlyMode(settings);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;

        String res = rh.executeSimpleRequest("_opendistro/_security/sslinfo?pretty");
        Assert.assertTrue(res.contains("TLS"));
        Assert.assertTrue(res.contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
        Assert.assertTrue(rh.executeSimpleRequest("_nodes/settings?pretty").contains(clusterInfo.clustername));
    }
}
