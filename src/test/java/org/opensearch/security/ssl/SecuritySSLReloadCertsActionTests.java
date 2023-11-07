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

package org.opensearch.security.ssl;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

public class SecuritySSLReloadCertsActionTests extends SingleClusterTest {

    private final ClusterConfiguration clusterConfiguration = ClusterConfiguration.DEFAULT;
    private final String GET_CERT_DETAILS_ENDPOINT = "_opendistro/_security/api/ssl/certs";
    private final String RELOAD_TRANSPORT_CERTS_ENDPOINT = "_opendistro/_security/api/ssl/transport/reloadcerts";
    private final String RELOAD_HTTP_CERTS_ENDPOINT = "_opendistro/_security/api/ssl/http/reloadcerts";
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();
    private final String HTTP_CERTIFICATES_LIST_KEY = "http_certificates_list";
    private final String TRANSPORT_CERTIFICATES_LIST_KEY = "transport_certificates_list";

    private final List<Map<String, String>> NODE_CERT_DETAILS = List.of(
        Map.of(
            "issuer_dn",
            "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
            "subject_dn",
            "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE",
            "san",
            "[[8, 1.2.3.4.5.5], [0, [2.5.4.3, node-1.example.com]], [2, node-1.example.com], [2, localhost], [7, 127.0.0.1]]",
            "not_before",
            "2023-04-14T13:22:53Z",
            "not_after",
            "2033-04-11T13:22:53Z"
        )
    );

    private final List<Map<String, String>> NEW_NODE_CERT_DETAILS = List.of(
        Map.of(
            "issuer_dn",
            "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
            "subject_dn",
            "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE",
            "san",
            "[[8, 1.2.3.4.5.5], [0, [2.5.4.3, node-1.example.com]], [2, node-1.example.com], [2, localhost], [7, 127.0.0.1]]",
            "not_before",
            "2023-04-14T13:23:00Z",
            "not_after",
            "2033-04-11T13:23:00Z"
        )
    );

    private String pemCertFilePath;
    private String pemKeyFilePath;
    private final String defaultCertFilePath = "ssl/reload/node.crt.pem";
    private final String defaultKeyFilePath = "ssl/reload/node.key.pem";
    private final String newCertFilePath = "ssl/reload/node-new.crt.pem";
    private final String newKeyFilePath = "ssl/reload/node-new.key.pem";

    @Before
    public void setUp() throws IOException {
        pemCertFilePath = testFolder.newFile("node-temp-cert.pem").getAbsolutePath();
        pemKeyFilePath = testFolder.newFile("node-temp-key.pem").getAbsolutePath();
    }

    @After
    public void checkClusterHealth() throws Exception {
        RestHelper rh = getRestHelperAdminUser();

        String clusterHealthResponse = rh.executeSimpleRequest("_cluster/health");
        final var clusterHealthResponseJson = DefaultObjectMapper.readTree(clusterHealthResponse);
        Assert.assertEquals("green", clusterHealthResponseJson.get("status").asText());

        String catNodesResponse = rh.executeSimpleRequest("_cat/nodes?format=json");
        final var catNodesResponseJson = DefaultObjectMapper.readTree(catNodesResponse);// (JSONArray) parser.parse(catNodesResponse);
        Assert.assertEquals(clusterConfiguration.getNodes(), catNodesResponseJson.size());
    }

    @Test
    public void testReloadTransportSSLCertsPass() throws Exception {
        initClusterWithTestCerts();
        RestHelper rh = getRestHelperAdminUser();
        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);

        final var expectedJsonResponse = getInitCertDetailsExpectedResponse();
        Assert.assertEquals(expectedJsonResponse, DefaultObjectMapper.readTree(certDetailsResponse));

        // Test Valid Case: Change transport file details to "ssl/pem/node-new.crt.pem" and "ssl/pem/node-new.key.pem"
        updateFiles(newCertFilePath, pemCertFilePath);
        updateFiles(newKeyFilePath, pemKeyFilePath);

        assertReloadCertificateSuccess(rh, "transport", getUpdatedCertDetailsExpectedResponse("transport"));
    }

    @Test
    public void testReloadHttpSSLCertsPass() throws Exception {
        initClusterWithTestCerts();

        RestHelper rh = getRestHelperAdminUser();

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        final var expectedJsonResponse = getInitCertDetailsExpectedResponse();
        Assert.assertEquals(expectedJsonResponse, DefaultObjectMapper.readTree(certDetailsResponse));

        // Test Valid Case: Change rest file details to "ssl/pem/node-new.crt.pem" and "ssl/pem/node-new.key.pem"
        updateFiles(newCertFilePath, pemCertFilePath);
        updateFiles(newKeyFilePath, pemKeyFilePath);

        assertReloadCertificateSuccess(rh, "http", getUpdatedCertDetailsExpectedResponse("http"));
    }

    @Test
    public void testSSLReloadFail_InvalidDNAndDate() throws Exception {
        initClusterWithTestCerts();
        RestHelper rh = getRestHelperAdminUser();
        // Test Invalid Case: Change transport file details to "ssl/pem/node-wrong.crt.pem"
        updateFiles("ssl/reload/node-wrong.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-wrong.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);
        Assert.assertEquals(500, reloadCertsResponse.getStatusCode());
        Assert.assertEquals(
            "OpenSearchSecurityException[Error while initializing transport SSL layer from PEM: java.lang.Exception: "
                + "New Certs do not have valid Issuer DN, Subject DN or SAN.]; nested: Exception[New Certs do not have valid Issuer DN, Subject DN or SAN.];",
            DefaultObjectMapper.readTree(reloadCertsResponse.getBody()).get("error").get("root_cause").get(0).get("reason").asText()
        );
    }

    @Test
    public void testReloadTransportSSLSameCertsPass() throws Exception {
        initClusterWithTestCerts();
        RestHelper rh = getRestHelperAdminUser();

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);

        final var expectedJsonResponse = getInitCertDetailsExpectedResponse();
        Assert.assertEquals(expectedJsonResponse, DefaultObjectMapper.readTree(certDetailsResponse));

        // Test Valid Case: Reload same certificate
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);

        assertReloadCertificateSuccess(rh, "transport", getInitCertDetailsExpectedResponse());
    }

    @Test
    public void testReloadHttpSSLSameCertsPass() throws Exception {
        initClusterWithTestCerts();
        RestHelper rh = getRestHelperAdminUser();

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        final var expectedJsonResponse = getInitCertDetailsExpectedResponse();
        Assert.assertEquals(expectedJsonResponse, DefaultObjectMapper.readTree(certDetailsResponse));

        // Test Valid Case: Reload same certificate
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);

        assertReloadCertificateSuccess(rh, "http", getInitCertDetailsExpectedResponse());
    }

    /**
     *
     * @param rh RestHelper to perform rest actions on the cluster
     * @param updateChannel certType/channel being updated, either http or transport
     * @param expectedCertResponse expected Certs after reload
     * @return True if all assertions pass
     * @throws Exception if rest api failed
     */
    private void assertReloadCertificateSuccess(RestHelper rh, String updateChannel, JsonNode expectedCertResponse) throws Exception {
        String reloadEndpoint = updateChannel.equals("http") ? RELOAD_HTTP_CERTS_ENDPOINT : RELOAD_TRANSPORT_CERTS_ENDPOINT;

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(reloadEndpoint, null);
        Assert.assertEquals(200, reloadCertsResponse.getStatusCode());
        final var expectedJsonResponse = DefaultObjectMapper.objectMapper.createObjectNode();
        expectedJsonResponse.put("message", String.format("updated %s certs", updateChannel));
        Assert.assertEquals(expectedJsonResponse.toString(), reloadCertsResponse.getBody());

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        Assert.assertEquals(expectedCertResponse, DefaultObjectMapper.readTree(certDetailsResponse));
    }

    private void updateFiles(String srcFile, String dstFile) {
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath(srcFile).toString(), dstFile);
    }

    private JsonNode getUpdatedCertDetailsExpectedResponse(String updateChannel) {
        String updateKey = (Objects.equals(updateChannel, "http")) ? HTTP_CERTIFICATES_LIST_KEY : TRANSPORT_CERTIFICATES_LIST_KEY;
        String oldKey = (Objects.equals(updateChannel, "http")) ? TRANSPORT_CERTIFICATES_LIST_KEY : HTTP_CERTIFICATES_LIST_KEY;
        final var updatedCertDetailsResponse = DefaultObjectMapper.objectMapper.createObjectNode();
        updatedCertDetailsResponse.set(updateKey, buildCertsInfoNode(NEW_NODE_CERT_DETAILS));
        updatedCertDetailsResponse.set(oldKey, buildCertsInfoNode(NODE_CERT_DETAILS));
        return updatedCertDetailsResponse;
    }

    private JsonNode getInitCertDetailsExpectedResponse() {
        final var initCertDetailsResponse = DefaultObjectMapper.objectMapper.createObjectNode();
        initCertDetailsResponse.set(HTTP_CERTIFICATES_LIST_KEY, buildCertsInfoNode(NODE_CERT_DETAILS));
        initCertDetailsResponse.set(TRANSPORT_CERTIFICATES_LIST_KEY, buildCertsInfoNode(NODE_CERT_DETAILS));
        return initCertDetailsResponse;
    }

    private JsonNode buildCertsInfoNode(final List<Map<String, String>> certsInfo) {
        final var nodeCertDetailsArray = DefaultObjectMapper.objectMapper.createArrayNode();
        certsInfo.forEach(m -> {
            final var o = DefaultObjectMapper.objectMapper.createObjectNode();
            m.forEach(o::put);
            nodeCertDetailsArray.add(o);
        });
        return nodeCertDetailsArray;
    }

    /**
     * kirk is configured as admin user in initTestCluster
     * @return RestHelper to execute rest actions against the cluster
     */
    private RestHelper getRestHelperAdminUser() {
        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/kirk-keystore.jks";
        return rh;
    }

    /**
     * spock is not an admin user
     * @return RestHelper to execute rest actions against the cluster
     */
    private RestHelper getRestHelperNonAdminUser() {
        RestHelper rh = restHelper();
        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "ssl/reload/spock-keystore.jks";
        return rh;
    }

    /**
     * Initialize cluster with default certificate and keys
     * @throws Exception
     */
    private void initClusterWithTestCerts() throws Exception {
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true);
    }

    /**
     * Helper method to initialize test cluster for SSL Certificate Reload Tests
     * @param transportPemCertFilePath Absolute Path to transport pem cert file
     * @param transportPemKeyFilePath Absolute Path to transport pem key file
     * @param httpPemCertFilePath Absolute Path to transport pem cert file
     * @param httpPemKeyFilePath Absolute Path to transport pem key file
     * @param sslCertReload Sets the ssl cert reload flag
     */
    private void initTestCluster(
        final String transportPemCertFilePath,
        final String transportPemKeyFilePath,
        final String httpPemCertFilePath,
        final String httpPemKeyFilePath,
        final boolean sslCertReload
    ) throws Exception {
        final Settings settings = Settings.builder()
            .putList(ConfigConstants.SECURITY_AUTHCZ_ADMIN_DN, "CN=kirk,OU=client,O=client,L=Test,C=DE")
            .putList(ConfigConstants.SECURITY_NODES_DN, "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE")
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, transportPemCertFilePath)
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, transportPemKeyFilePath)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/root-ca.pem")
            )
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMCERT_FILEPATH, httpPemCertFilePath) // "ssl/reload/node.crt.pem"
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_PEMKEY_FILEPATH, httpPemKeyFilePath) // "ssl/reload/node.key.pem"
            .put(
                SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/root-ca.pem")
            )
            .put(ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED, sslCertReload)
            .build();

        final Settings initTransportClientSettings = Settings.builder()
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/truststore.jks")
            )
            .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
            .put(
                SSLConfigConstants.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH,
                FileHelper.getAbsoluteFilePathFromClassPath("ssl/reload/kirk-keystore.jks")
            )
            .build();

        setup(initTransportClientSettings, new DynamicSecurityConfig(), settings, true, clusterConfiguration);
    }

}
