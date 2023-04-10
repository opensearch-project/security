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

package org.opensearch.security.dlic.rest.api;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;

public class SslCertsApiTest extends AbstractRestApiUnitTest {

    static final String HTTP_CERTS = "http";

    static final String TRANSPORT_CERTS = "transport";

    private final static List<Map<String, String>> EXPECTED_CERTIFICATES =
            ImmutableList.of(
                    ImmutableMap.of(
                            "issuer_dn", "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
                            "subject_dn", "CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE",
                            "san", "[[2, node-0.example.com], [2, localhost], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
                            "not_before", "2018-05-05T14:37:09Z",
                            "not_after", "2028-05-02T14:37:09Z"
                    ),
                    ImmutableMap.of(
                            "issuer_dn", "CN=Example Com Inc. Root CA,OU=Example Com Inc. Root CA,O=Example Com Inc.,DC=example,DC=com",
                            "subject_dn", "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
                            "san", "",
                            "not_before", "2018-05-05T14:37:08Z",
                            "not_after", "2028-05-04T14:37:08Z"
                    )
            );

    private final static String EXPECTED_CERTIFICATES_BY_TYPE;
    static {
        try {
            EXPECTED_CERTIFICATES_BY_TYPE = DefaultObjectMapper.objectMapper.writeValueAsString(
                    ImmutableMap.of(
                            "http_certificates_list", EXPECTED_CERTIFICATES,
                            "transport_certificates_list", EXPECTED_CERTIFICATES
                    )
            );
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
    private final Header restApiCertsInfoAdminHeader = encodeBasicHeader("rest_api_admin_ssl_info", "rest_api_admin_ssl_info");

    private final Header restApiReloadCertsAdminHeader = encodeBasicHeader("rest_api_admin_ssl_reloadcerts", "rest_api_admin_ssl_reloadcerts");

    private final Header restApiHeader = encodeBasicHeader("test", "test");


    public String certsInfoEndpoint() {
        return PLUGINS_PREFIX + "/api/ssl/certs";
    }

    public String certsReloadEndpoint(final String certType) {
        return String.format("%s/api/ssl/%s/reloadcerts", PLUGINS_PREFIX, certType);
    }

    private void verifyHasNoAccess() throws Exception {
        final Header adminCredsHeader = encodeBasicHeader("admin", "admin");
        // No creds, no admin certificate - UNAUTHORIZED
        rh.sendAdminCertificate = false;
        HttpResponse response = rh.executeGetRequest(certsInfoEndpoint());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executeGetRequest(certsInfoEndpoint(), adminCredsHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        response = rh.executeGetRequest(certsInfoEndpoint(), restApiHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }

    @Test
    public void testCertsInfo() throws Exception {
        setup();
        verifyHasNoAccess();
        sendAdminCert();
        HttpResponse response = rh.executeGetRequest(certsInfoEndpoint());
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        Assert.assertEquals(EXPECTED_CERTIFICATES_BY_TYPE, response.getBody());

    }

    @Test
    public void testCertsInfoRestAdmin() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());
        verifyHasNoAccess();
        rh.sendAdminCertificate = false;
        Assert.assertEquals(EXPECTED_CERTIFICATES_BY_TYPE, loadCerts(restApiAdminHeader));
        Assert.assertEquals(EXPECTED_CERTIFICATES_BY_TYPE, loadCerts(restApiCertsInfoAdminHeader));
    }

    private String loadCerts(final Header... header) throws Exception {
        HttpResponse response = rh.executeGetRequest(certsInfoEndpoint(), restApiAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
        return response.getBody();
    }

    @Test
    public void testReloadCertsNotAvailableByDefault() throws Exception {
        setupWithRestRoles();

        sendAdminCert();
        verifyReloadCertsNotAvailable(HttpStatus.SC_BAD_REQUEST);

        rh.sendAdminCertificate = false;
        verifyReloadCertsNotAvailable(HttpStatus.SC_FORBIDDEN, restApiAdminHeader);
        verifyReloadCertsNotAvailable(HttpStatus.SC_FORBIDDEN, restApiReloadCertsAdminHeader);
    }

    private void verifyReloadCertsNotAvailable(final int expectedStatus, final Header... header) {
        HttpResponse response = rh.executePutRequest(certsReloadEndpoint(HTTP_CERTS), "{}", header);
        Assert.assertEquals(response.getBody(), expectedStatus, response.getStatusCode());
        response = rh.executePutRequest(certsReloadEndpoint(TRANSPORT_CERTS), "{}", header);
        Assert.assertEquals(response.getBody(), expectedStatus, response.getStatusCode());
    }

    @Test
    public void testReloadCertsWrongCertsType() throws Exception {
        setupWithRestRoles(reloadEnabled());
        sendAdminCert();
        HttpResponse response = rh.executePutRequest(certsReloadEndpoint("aaaaa"), "{}");
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        rh.sendAdminCertificate = false;
        response = rh.executePutRequest(certsReloadEndpoint("bbbb"), "{}", restApiAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executePutRequest(certsReloadEndpoint("cccc"), "{}", restApiReloadCertsAdminHeader);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_FORBIDDEN, response.getStatusCode());

    }

    private void sendAdminCert() {
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;
    }

    Settings reloadEnabled() {
        return Settings.builder()
                .put(ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED, true)
                .build();
    }

}
