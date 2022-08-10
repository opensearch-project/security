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

package org.opensearch.security.sanity.tests;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import org.apache.http.HttpHost;

import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import static org.opensearch.commons.ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_ENABLED;
import static org.opensearch.commons.ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH;
import static org.opensearch.commons.ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD;
import static org.opensearch.commons.ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD;
import static org.opensearch.commons.ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_PEMCERT_FILEPATH;

/**
 * Overrides OpenSearchRestTestCase to fit the use-case for testing
 * against remote cluster for Security Plugin.
 *
 * Modify this test class as needed
 */
@SuppressWarnings("unchecked")
public class SecurityRestTestCase extends OpenSearchRestTestCase {

    private static final String CERT_FILE_DIRECTORY = "sanity-tests/";
    private boolean isHttps() {
        return System.getProperty("https").equals("true");
    }
    private boolean securityEnabled() {
        return System.getProperty("security.enabled").equals("true");
    }

    @Override
    protected Settings restAdminSettings(){

        return Settings
                .builder()
                .put("http.port", 9200)
                .put(OPENSEARCH_SECURITY_SSL_HTTP_ENABLED, isHttps())
                .put(OPENSEARCH_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, CERT_FILE_DIRECTORY + "opensearch-node.pem")
                .put("plugins.security.ssl.http.pemkey_filepath", CERT_FILE_DIRECTORY + "opensearch-node-key.pem")
                .put("plugins.security.ssl.transport.pemtrustedcas_filepath", CERT_FILE_DIRECTORY + "root-ca.pem")
                .put(OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, CERT_FILE_DIRECTORY + "test-kirk.jks")
                .put(OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD, "changeit")
                .put(OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD, "changeit")
                .build();
    }

    @Override
    protected RestClient buildClient(Settings settings, HttpHost[] hosts) throws IOException {

        if(securityEnabled()){
            String keystore = settings.get(OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH);

            if(keystore != null){
                // create adminDN (super-admin) client
                File file = new File(getClass().getClassLoader().getResource(CERT_FILE_DIRECTORY).getFile());
                Path configPath = PathUtils.get(file.toURI()).getParent().toAbsolutePath();
                return new SecureRestClientBuilder(settings, configPath).setSocketTimeout(60000).build();
            }

            // create client with passed user
            String userName = System.getProperty("user");
            String password = System.getProperty("password");
            return new SecureRestClientBuilder(hosts, isHttps(), userName, password).setSocketTimeout(60000).build();
        }
        else {
            RestClientBuilder builder = RestClient.builder(hosts);
            configureClient(builder, settings);
            builder.setStrictDeprecationMode(true);
            return builder.build();
        }
    }

    protected static Map<String, Object> getAsMapByAdmin(final String endpoint) throws IOException {
        Response response = adminClient().performRequest(new Request("GET", endpoint));
        return responseAsMap(response);
    }
}
