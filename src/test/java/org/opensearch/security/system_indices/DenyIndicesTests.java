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

package org.opensearch.security.system_indices;

import org.apache.hc.core5.http.Header;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 *  Test for opendistro system indices, to restrict configured indices access to adminDn
 *  Refer:    "plugins.security.system_indices.enabled"
 *            "plugins.security.system_indices.indices";
 */

public class DenyIndicesTests extends SingleClusterTest {
    private static final List<String> listOfIndexesToTest = Arrays.asList(".opendistro_security");
    private static final String matchAllQuery = "{\n\"query\": {\"match_all\": {}}}";
    private static final String allAccessUser = "admin_all_access";
    private static final Header allAccessUserHeader = encodeBasicHeader(allAccessUser, allAccessUser);
    private static final String generalErrorMessage = String.format(
        "no permissions for [] and User [name=%s, backend_roles=[], requestedTenant=null]",
        allAccessUser
    );

    private void setupDenyIndicesEnabledWithSsl(Boolean securedIndicesAdditionalControlenable) throws Exception {

        Settings denyIndexSettings = Settings.builder()
            .put(ConfigConstants.SECURITY_SYSTEM_INDICES_ADDITIONAL_CONTROL_ENABLED_KEY, securedIndicesAdditionalControlenable)
            .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, listOfIndexesToTest)
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .put("path.repo", repositoryPath.getRoot().getAbsolutePath())
            .build();

        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setConfig("config_system_indices.yml")
                .setSecurityRoles("roles_system_indices.yml")
                .setSecurityInternalUsers("internal_users_system_indices.yml")
                .setSecurityRolesMapping("roles_mapping_system_indices.yml"),
            denyIndexSettings,
            true
        );
    }

    /**
     * Creates a set of test indices and indexes one document into each index.
     *
     * @throws Exception
     */

    private RestHelper keyStoreRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.keystore = "kirk-keystore.jks";
        restHelper.enableHTTPClientSSL = true;
        restHelper.trustHTTPServerCertificate = true;
        restHelper.sendAdminCertificate = true;
        return restHelper;
    }

    private RestHelper sslRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.enableHTTPClientSSL = true;
        return restHelper;
    }

    /***************************************************************************************************************************
     * Search api tests. Search is a special case.
     ***************************************************************************************************************************/

    private void validateSearchResponse(RestHelper.HttpResponse response, int expectecdHits) throws IOException {
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
        assertEquals(RestStatus.OK, searchResponse.status());
        assertEquals(expectecdHits, searchResponse.getHits().getHits().length);
        assertEquals(0, searchResponse.getFailedShards());
        assertEquals(5, searchResponse.getSuccessfulShards());
    }

    @Test
    public void testSearchWithDenyIndicesAsSuperAdmin() throws Exception {
        setupDenyIndicesEnabledWithSsl(true);
        RestHelper restHelper = keyStoreRestHelper();

        // search system indices
        for (String index : listOfIndexesToTest) {
            validateSearchResponse(restHelper.executePostRequest(index + "/_search", matchAllQuery), 10);
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchWithDenyIndicesShouldFailAsAdmin() throws Exception {
        setupDenyIndicesEnabledWithSsl(true);
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader);
            assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
            MatcherAssert.assertThat(
                response.getBody(),
                Matchers.containsStringIgnoringCase(
                    "\"type\":\"security_exception\",\"reason\":\"no permissions for [] and User [name=admin_all_access, backend_roles=[], requestedTenant=null]\"}"
                )
            );
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

    @Test
    public void testSearchWithDenyIndicesShouldSuccedAsAdminNoAdditinalAccesslControl() throws Exception {
        setupDenyIndicesEnabledWithSsl(false);
        RestHelper restHelper = sslRestHelper();

        // search system indices
        for (String index : listOfIndexesToTest) {
            RestHelper.HttpResponse response = restHelper.executePostRequest(index + "/_search", matchAllQuery, allAccessUserHeader);
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
            MatcherAssert.assertThat(response.getBody(), Matchers.containsStringIgnoringCase("\"failed\":0"));
        }

        // search all indices
        RestHelper.HttpResponse response = restHelper.executePostRequest("/_search", matchAllQuery, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
    }

}
