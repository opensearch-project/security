/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.ssl;

import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.cluster.ClusterConfiguration;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import net.minidev.json.JSONObject;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.io.File;
import java.util.List;
import java.util.Map;

public class OpenDistroSecuritySSLReloadCertsActionTests extends SingleClusterTest {

    private final String GET_CERT_DETAILS_ENDPOINT = "_opendistro/_security/api/ssl/certs";
    private final String RELOAD_TRANSPORT_CERTS_ENDPOINT = "_opendistro/_security/api/ssl/transport/reloadcerts";
    private final String RELOAD_HTTP_CERTS_ENDPOINT = "_opendistro/_security/api/ssl/http/reloadcerts";

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    private final List<Map<String, String>> NODE_CERT_DETAILS = ImmutableList.of(
        ImmutableMap.of(
        "issuer_dn", "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
        "subject_dn", "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE",
            "san", "[[2, node-1.example.com], [2, localhost], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
        "not_before", "2020-02-17T16:19:25Z",
        "not_after", "2022-02-16T16:19:25Z"
        ));

    private final List<Map<String, String>> NEW_NODE_CERT_DETAILS = ImmutableList.of(
        ImmutableMap.of(
            "issuer_dn", "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
            "subject_dn", "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE",
            "san", "[[2, node-1.example.com], [2, localhost], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
            "not_before", "2020-02-18T14:11:28Z",
            "not_after", "2022-02-17T14:11:28Z"
        )
    );

    @Test
    public void testReloadTransportSSLCertsPass() throws Exception {
        final String pemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        final String pemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), pemKeyFilePath);

        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);

        JSONObject expectedJsonResponse = new JSONObject();
        expectedJsonResponse.appendField("http_certificates_list", NODE_CERT_DETAILS);
        expectedJsonResponse.appendField("transport_certificates_list", NODE_CERT_DETAILS);
        Assert.assertEquals(expectedJsonResponse.toString(), certDetailsResponse);

        // Test Valid Case: Change transport file details to "ssl/pem/node-new.crt.pem" and "ssl/pem/node-new.key.pem"
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-new.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-new.key.pem").toString(), pemKeyFilePath);
        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);

        Assert.assertEquals(200, reloadCertsResponse.getStatusCode());
        expectedJsonResponse = new JSONObject();
        expectedJsonResponse.appendField("message", "updated transport certs");
        Assert.assertEquals(expectedJsonResponse.toString(), reloadCertsResponse.getBody());

        certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        expectedJsonResponse = new JSONObject();
        expectedJsonResponse.appendField("http_certificates_list", NODE_CERT_DETAILS);
        expectedJsonResponse.appendField("transport_certificates_list", NEW_NODE_CERT_DETAILS);
        Assert.assertEquals(expectedJsonResponse.toString(), certDetailsResponse);
    }

    @Test
    public void testReloadHttpSSLCertsPass() throws Exception {
        final String pemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        final String pemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), pemKeyFilePath);

        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        JSONObject expectedJsonResponse = new JSONObject();
        expectedJsonResponse.appendField("http_certificates_list", NODE_CERT_DETAILS);
        expectedJsonResponse.appendField("transport_certificates_list", NODE_CERT_DETAILS);
        Assert.assertEquals(expectedJsonResponse.toString(), certDetailsResponse);

        // Test Valid Case: Change rest file details to "ssl/pem/node-new.crt.pem" and "ssl/pem/node-new.key.pem"
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-new.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-new.key.pem").toString(), pemKeyFilePath);
        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_HTTP_CERTS_ENDPOINT, null);

        Assert.assertEquals(200, reloadCertsResponse.getStatusCode());
        expectedJsonResponse = new JSONObject();
        expectedJsonResponse.appendField("message", "updated http certs");
        Assert.assertEquals(expectedJsonResponse.toString(), reloadCertsResponse.getBody());

        certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        expectedJsonResponse = new JSONObject();
        expectedJsonResponse.appendField("http_certificates_list", NEW_NODE_CERT_DETAILS);
        expectedJsonResponse.appendField("transport_certificates_list", NODE_CERT_DETAILS);
        Assert.assertEquals(expectedJsonResponse.toString(), certDetailsResponse);
    }

    @Test
    public void testReloadHttpSSLCerts_FailWrongUri() throws Exception {

        final String pemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        final String pemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), pemKeyFilePath);

        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest("_opendistro/_security/api/ssl/wrong/reloadcerts", null);
        JSONObject expectedResponse = new JSONObject();
        // Note: toString and toJSONString replace / with \/. This helps get rid of the additional \ character.
        expectedResponse.put("message", "invalid uri path, please use /_opendistro/_security/api/ssl/http/reload or /_opendistro/_security/api/ssl/transport/reload");
        final String expectedResponseString = expectedResponse.toString().replace("\\", "");
        Assert.assertEquals(expectedResponseString, reloadCertsResponse.getBody());
    }


    @Test
    public void testSSLReloadFail_UnAuthorizedUser() throws Exception {
        final String transportPemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        final String transportPemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), transportPemKeyFilePath);

        initTestCluster(transportPemCertFilePath, transportPemKeyFilePath, transportPemCertFilePath, transportPemKeyFilePath, true);

        // Test endpoint for non-admin user
        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/spock-keystore.jks";

        final RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);
        Assert.assertEquals(401, reloadCertsResponse.getStatusCode());
        Assert.assertEquals("Unauthorized", reloadCertsResponse.getStatusReason());
    }


    @Test
    public void testSSLReloadFail_InvalidDNAndDate() throws Exception {
        final String pemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        final String pemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), pemKeyFilePath);

        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true);

        // Test Invalid Case: Change transport file details to "ssl/pem/node-wrong.crt.pem"
        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-wrong.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node-wrong.key.pem").toString(), pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);
        Assert.assertEquals(500, reloadCertsResponse.getStatusCode());
        JSONObject expectedResponse = new JSONObject();
        expectedResponse.appendField("error", "ElasticsearchSecurityException[Error while initializing transport SSL layer from PEM: java.lang.Exception: " +
            "New Certs do not have valid Issuer DN, Subject DN or SAN.]; nested: Exception[New Certs do not have valid Issuer DN, Subject DN or SAN.];");
        Assert.assertEquals(expectedResponse.toString(), reloadCertsResponse.getBody());


        // Test Invalid Case: Reloading with same certificates
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), pemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), pemKeyFilePath);

        reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);
        Assert.assertEquals(500, reloadCertsResponse.getStatusCode());
        expectedResponse = new JSONObject();
        expectedResponse.appendField("error", "ElasticsearchSecurityException[Error while initializing transport SSL layer from PEM: java.lang.Exception: New certificates should not expire before the current ones.]; nested: Exception[New certificates should not expire before the current ones.];");
        Assert.assertEquals(expectedResponse.toString(), reloadCertsResponse.getBody());
    }

    @Test
    public void testSSLReloadFail_NoReloadSet() throws Exception {
        final File transportPemCertFile = testFolder.newFile("node-temp-cert.pem");
        final File transportPemKeyFile = testFolder.newFile("node-temp-key.pem");
        final String transportPemCertFilePath = transportPemCertFile.getAbsolutePath();
        final String transportPemKeyFilePath = transportPemKeyFile.getAbsolutePath();
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.crt.pem").toString(), transportPemCertFilePath);
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/node.key.pem").toString(), transportPemKeyFilePath);

        // This is when SSLCertReload property is set to false
        initTestCluster(transportPemCertFilePath, transportPemKeyFilePath, transportPemCertFilePath, transportPemKeyFilePath, false);

        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";

        final RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);
        Assert.assertEquals(400, reloadCertsResponse.getStatusCode());
        JSONObject expectedResponse = new JSONObject();
        expectedResponse.appendField("error", "no handler found for uri [/_opendistro/_security/api/ssl/transport/reloadcerts] and method [PUT]");
        // Note: toString and toJSONString replace / with \/. This helps get rid of the additional \ character.
        final String expectedResponseString = expectedResponse.toString().replace("\\", "");
        Assert.assertEquals(expectedResponseString, reloadCertsResponse.getBody());
    }

    /**
     * Helper method to initialize test cluster for SSL Certificate Reload Tests
     * @param transportPemCertFilePath Absolute Path to transport pem cert file
     * @param transportPemKeyFilePath Absolute Path to transport pem key file
     * @param httpPemCertFilePath Absolute Path to transport pem cert file
     * @param httpPemKeyFilePath Absolute Path to transport pem key file
     * @param sslCertReload Sets the ssl cert reload flag
     */
    private void initTestCluster(final String transportPemCertFilePath, final String transportPemKeyFilePath, final String httpPemCertFilePath, final String httpPemKeyFilePath, final boolean sslCertReload) throws Exception {
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN, "CN=kirk,OU=client,O=client,L=Test,C=DE")
            .putList(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN, "C=DE,L=Test,O=Test,OU=SSL,CN=node-1.example.com")
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, transportPemCertFilePath)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, transportPemKeyFilePath)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/root-ca.pem"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, httpPemCertFilePath) // "ssl/reload/node.crt.pem"
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH, httpPemKeyFilePath) // "ssl/reload/node.key.pem"
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/root-ca.pem"))
            .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD_ENABLED, sslCertReload)
            .build();

        final Settings initTransportClientSettings = Settings.builder()
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/truststore.jks"))
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/kirk-keystore.jks"))
            .build();

        setup(initTransportClientSettings, new DynamicSecurityConfig(), settings, true, ClusterConfiguration.DEFAULT);
    }

}
