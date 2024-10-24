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

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.After;
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class SecuritySSLReloadCertsActionTests extends SingleClusterTest {

    private final ClusterConfiguration clusterConfiguration = ClusterConfiguration.DEFAULT;
    private final String GET_CERT_DETAILS_ENDPOINT = "_opendistro/_security/api/ssl/certs";
    private final String RELOAD_TRANSPORT_CERTS_ENDPOINT = "_opendistro/_security/api/ssl/transport/reloadcerts";
    private final String RELOAD_HTTP_CERTS_ENDPOINT = "_opendistro/_security/api/ssl/http/reloadcerts";
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    private final List<Map<String, String>> INITIAL_NODE_CERT_DETAILS = List.of(
        Map.of(
            "issuer_dn",
            "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
            "subject_dn",
            "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE",
            "san",
            "[[0, [2.5.4.3, node-1.example.com]], [2, localhost], [2, node-1.example.com], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
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
            "[[0, [2.5.4.3, node-1.example.com]], [2, localhost], [2, node-1.example.com], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
            "not_before",
            "2023-04-14T13:23:00Z",
            "not_after",
            "2033-04-11T13:23:00Z"
        )
    );

    private final List<Map<String, String>> NEW_CA_NODE_CERT_DETAILS = List.of(
        Map.of(
            "issuer_dn",
            "CN=Example Com Inc. Secondary Signing CA,OU=Example Com Inc. Secondary Signing CA,O=Example Com Inc.,DC=example,DC=com",
            "subject_dn",
            "CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE",
            "san",
            "[[2, localhost], [2, node-1.example.com], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
            "not_before",
            "2024-09-17T00:15:48Z",
            "not_after",
            "2034-09-15T00:15:48Z"
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
        assertThat(clusterHealthResponseJson.get("status").asText(), is("green"));

        String catNodesResponse = rh.executeSimpleRequest("_cat/nodes?format=json");
        final var catNodesResponseJson = DefaultObjectMapper.readTree(catNodesResponse);// (JSONArray) parser.parse(catNodesResponse);
        assertThat(catNodesResponseJson.size(), is(clusterConfiguration.getNodes()));
    }

    @Test
    public void testReloadTransportSSLCertsPass() throws Exception {
        initClusterWithTestCerts();
        RestHelper rh = getRestHelperAdminUser();
        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);

        final var expectedJsonResponse = getInitCertDetailsExpectedResponse();
        assertThat(DefaultObjectMapper.readTree(certDetailsResponse), is(expectedJsonResponse));

        // Test Valid Case: Change transport file details to "ssl/pem/node-new.crt.pem" and "ssl/pem/node-new.key.pem"
        updateFiles(newCertFilePath, pemCertFilePath);
        updateFiles(newKeyFilePath, pemKeyFilePath);

        assertReloadCertificateSuccess(rh, "transport", getCertDetailsExpectedResponse(INITIAL_NODE_CERT_DETAILS, NEW_NODE_CERT_DETAILS));
    }

    @Test
    public void testReloadHttpSSLCertsPass() throws Exception {
        initClusterWithTestCerts();

        RestHelper rh = getRestHelperAdminUser();

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        final var expectedJsonResponse = getInitCertDetailsExpectedResponse();
        assertThat(DefaultObjectMapper.readTree(certDetailsResponse), is(expectedJsonResponse));

        // Test Valid Case: Change rest file details to "ssl/pem/node-new.crt.pem" and "ssl/pem/node-new.key.pem"
        updateFiles(newCertFilePath, pemCertFilePath);
        updateFiles(newKeyFilePath, pemKeyFilePath);

        assertReloadCertificateSuccess(rh, "http", getCertDetailsExpectedResponse(NEW_NODE_CERT_DETAILS, INITIAL_NODE_CERT_DETAILS));
    }

    @Test
    public void testSSLReloadFail_InvalidDNAndDate() throws Exception {
        initClusterWithTestCerts();
        RestHelper rh = getRestHelperAdminUser();
        // Test Invalid Case: Change transport file details to "ssl/pem/node-wrong.crt.pem"
        updateFiles("ssl/reload/node-wrong.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-wrong.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);
        assertThat(reloadCertsResponse.getStatusCode(), is(500));
        assertThat(
            DefaultObjectMapper.readTree(reloadCertsResponse.getBody()).get("error").get("root_cause").get(0).get("reason").asText(),
            is(
                "java.security.cert.CertificateException: "
                    + "New certificates do not have valid Subject DNs. Current Subject DNs [CN=node-1.example.com,OU=SSL,O=Test,L=Test,C=DE] "
                    + "new Subject DNs [CN=node-2.example.com,OU=SSL,O=Test,L=Test,C=DE]"
            )
        );
    }

    @Test
    public void testReloadTransportSSLSameCertsPass() throws Exception {
        initClusterWithTestCerts();
        RestHelper rh = getRestHelperAdminUser();

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);

        final var expectedJsonResponse = getInitCertDetailsExpectedResponse();
        assertThat(DefaultObjectMapper.readTree(certDetailsResponse), is(expectedJsonResponse));

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
        assertThat(DefaultObjectMapper.readTree(certDetailsResponse), is(expectedJsonResponse));

        // Test Valid Case: Reload same certificate
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);

        assertReloadCertificateSuccess(rh, "http", getInitCertDetailsExpectedResponse());
    }

    @Test
    public void testReloadHttpCertDifferentTrustChain_skipDnValidationPass() throws Exception {
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true, false, true);

        RestHelper rh = getRestHelperAdminUser();
        // Change http certs to one signed by a different CA than the previous one
        updateFiles("ssl/reload/node-new-ca.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-new-ca.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_HTTP_CERTS_ENDPOINT, null);

        assertThat(reloadCertsResponse.getStatusCode(), is(200));
        final var expectedJsonResponse = DefaultObjectMapper.objectMapper.createObjectNode();
        expectedJsonResponse.put("message", "updated http certs");
        assertThat(reloadCertsResponse.getBody(), is(expectedJsonResponse.toString()));

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        assertThat(
            DefaultObjectMapper.readTree(certDetailsResponse),
            is(getCertDetailsExpectedResponse(NEW_CA_NODE_CERT_DETAILS, INITIAL_NODE_CERT_DETAILS))
        );
    }

    @Test
    public void testReloadHttpCertDifferentTrustChain_noSkipDnValidationFail() throws Exception {
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true, true, true);

        RestHelper rh = getRestHelperAdminUser();
        // Change http certs to one signed by a different CA than the previous one
        updateFiles("ssl/reload/node-new-ca.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-new-ca.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_HTTP_CERTS_ENDPOINT, null);

        assertThat(reloadCertsResponse.getStatusCode(), is(500));
        assertThat(
            DefaultObjectMapper.readTree(reloadCertsResponse.getBody()).get("error").get("root_cause").get(0).get("reason").asText(),
            is(
                "OpenSearchSecurityException[Error while initializing http SSL layer from PEM: java.lang.Exception: "
                    + "New Certs do not have valid Issuer DN, Subject DN or SAN.]; nested: Exception[New Certs do not have valid Issuer DN, Subject DN or SAN.];"
            )
        );
    }

    @Test
    public void testReloadHttpCertDifferentTrustChain_defaultSettingValidationFail() throws Exception {
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true, null, null);

        RestHelper rh = getRestHelperAdminUser();
        // Change http certs to one signed by a different CA than the previous one
        updateFiles("ssl/reload/node-new-ca.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-new-ca.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_HTTP_CERTS_ENDPOINT, null);

        assertThat(reloadCertsResponse.getStatusCode(), is(500));
        assertThat(
            DefaultObjectMapper.readTree(reloadCertsResponse.getBody()).get("error").get("root_cause").get(0).get("reason").asText(),
            is(
                "OpenSearchSecurityException[Error while initializing http SSL layer from PEM: java.lang.Exception: "
                    + "New Certs do not have valid Issuer DN, Subject DN or SAN.]; nested: Exception[New Certs do not have valid Issuer DN, Subject DN or SAN.];"
            )
        );
    }

    @Test
    public void testReloadTransportCertDifferentTrustChain_skipDnValidationPass() throws Exception {
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true, true, false);

        RestHelper rh = getRestHelperAdminUser();
        // Change transport certs to one signed by a different CA than the previous one
        updateFiles("ssl/reload/node-new-ca.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-new-ca.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);

        assertThat(reloadCertsResponse.getStatusCode(), is(200));
        final var expectedJsonResponse = DefaultObjectMapper.objectMapper.createObjectNode();
        expectedJsonResponse.put("message", "updated transport certs");
        assertThat(reloadCertsResponse.getBody(), is(expectedJsonResponse.toString()));

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        assertThat(
            DefaultObjectMapper.readTree(certDetailsResponse),
            is(getCertDetailsExpectedResponse(INITIAL_NODE_CERT_DETAILS, NEW_CA_NODE_CERT_DETAILS))
        );
    }

    @Test
    public void testReloadTransportCertDifferentTrustChain_noSkipDnValidationFail() throws Exception {
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true, true, true);

        RestHelper rh = getRestHelperAdminUser();
        // Change transport certs to one signed by a different CA than the previous one
        updateFiles("ssl/reload/node-new-ca.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-new-ca.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);

        assertThat(reloadCertsResponse.getStatusCode(), is(500));
        assertThat(
            DefaultObjectMapper.readTree(reloadCertsResponse.getBody()).get("error").get("root_cause").get(0).get("reason").asText(),
            is(
                "OpenSearchSecurityException[Error while initializing transport SSL layer from PEM: java.lang.Exception: "
                    + "New Certs do not have valid Issuer DN, Subject DN or SAN.]; nested: Exception[New Certs do not have valid Issuer DN, Subject DN or SAN.];"
            )
        );
    }

    @Test
    public void testReloadTransportCertDifferentTrustChain_defaultSettingValidationFail() throws Exception {
        updateFiles(defaultCertFilePath, pemCertFilePath);
        updateFiles(defaultKeyFilePath, pemKeyFilePath);
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true, null, null);

        RestHelper rh = getRestHelperAdminUser();
        // Change transport certs to one signed by a different CA than the previous one
        updateFiles("ssl/reload/node-new-ca.crt.pem", pemCertFilePath);
        updateFiles("ssl/reload/node-new-ca.key.pem", pemKeyFilePath);

        RestHelper.HttpResponse reloadCertsResponse = rh.executePutRequest(RELOAD_TRANSPORT_CERTS_ENDPOINT, null);

        assertThat(reloadCertsResponse.getStatusCode(), is(500));
        assertThat(
            DefaultObjectMapper.readTree(reloadCertsResponse.getBody()).get("error").get("root_cause").get(0).get("reason").asText(),
            is(
                "OpenSearchSecurityException[Error while initializing transport SSL layer from PEM: java.lang.Exception: "
                    + "New Certs do not have valid Issuer DN, Subject DN or SAN.]; nested: Exception[New Certs do not have valid Issuer DN, Subject DN or SAN.];"
            )
        );
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
        assertThat(reloadCertsResponse.getStatusCode(), is(200));
        final var expectedJsonResponse = DefaultObjectMapper.objectMapper.createObjectNode();
        expectedJsonResponse.put("message", String.format("updated %s certs", updateChannel));
        assertThat(reloadCertsResponse.getBody(), is(expectedJsonResponse.toString()));

        String certDetailsResponse = rh.executeSimpleRequest(GET_CERT_DETAILS_ENDPOINT);
        assertThat(DefaultObjectMapper.readTree(certDetailsResponse), is(expectedCertResponse));
    }

    private void updateFiles(String srcFile, String dstFile) {
        FileHelper.copyFileContents(FileHelper.getAbsoluteFilePathFromClassPath(srcFile).toString(), dstFile);
    }

    private JsonNode getCertDetailsExpectedResponse(
        List<Map<String, String>> httpCertDetails,
        List<Map<String, String>> transportCertDetails
    ) {
        final var updatedCertDetailsResponse = DefaultObjectMapper.objectMapper.createObjectNode();
        updatedCertDetailsResponse.set("http_certificates_list", buildCertsInfoNode(httpCertDetails));
        updatedCertDetailsResponse.set("transport_certificates_list", buildCertsInfoNode(transportCertDetails));
        return updatedCertDetailsResponse;
    }

    private JsonNode getInitCertDetailsExpectedResponse() {
        return getCertDetailsExpectedResponse(INITIAL_NODE_CERT_DETAILS, INITIAL_NODE_CERT_DETAILS);
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
        initTestCluster(pemCertFilePath, pemKeyFilePath, pemCertFilePath, pemKeyFilePath, true, true, true);
    }

    /**
     * Helper method to initialize test cluster for SSL Certificate Reload Tests
     * @param transportPemCertFilePath             Absolute Path to transport pem cert file
     * @param transportPemKeyFilePath              Absolute Path to transport pem key file
     * @param httpPemCertFilePath                  Absolute Path to transport pem cert file
     * @param httpPemKeyFilePath                   Absolute Path to transport pem key file
     * @param sslCertReload                        Sets the ssl cert reload flag
     * @param httpEnforceReloadDnVerification      Sets the http enforce reload dn verification flag if non-null
     * @param transportEnforceReloadDnVerification Sets the transport enforce reload dn verification flag if non-null
     */
    private void initTestCluster(
        final String transportPemCertFilePath,
        final String transportPemKeyFilePath,
        final String httpPemCertFilePath,
        final String httpPemKeyFilePath,
        final boolean sslCertReload,
        final Boolean httpEnforceReloadDnVerification,
        final Boolean transportEnforceReloadDnVerification
    ) throws Exception {
        final Settings.Builder settingsBuilder = Settings.builder()
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
            .put(ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED, sslCertReload);

        if (httpEnforceReloadDnVerification != null) settingsBuilder.put(
            SSLConfigConstants.SECURITY_SSL_HTTP_ENFORCE_CERT_RELOAD_DN_VERIFICATION,
            httpEnforceReloadDnVerification
        );

        if (transportEnforceReloadDnVerification != null) settingsBuilder.put(
            SSLConfigConstants.SECURITY_SSL_TRANSPORT_ENFORCE_CERT_RELOAD_DN_VERIFICATION,
            transportEnforceReloadDnVerification
        );

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

        setup(initTransportClientSettings, new DynamicSecurityConfig(), settingsBuilder.build(), true, clusterConfiguration);
    }

}
