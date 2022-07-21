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
                .put(OPENSEARCH_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, CERT_FILE_DIRECTORY + "esnode.pem")
                .put("plugins.security.ssl.http.pemkey_filepath", CERT_FILE_DIRECTORY + "esnode-key.pem")
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
