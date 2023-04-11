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

package org.opensearch.security.privileges;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.junit.Assert.assertEquals;

public class PrivilegesEvaluatorTest extends SingleClusterTest {
    private static final Header NegativeLookaheadUserHeader = encodeBasicHeader("negative_lookahead_user", "negative_lookahead_user");
    private static final Header NegatedRegexUserHeader = encodeBasicHeader("negated_regex_user", "negated_regex_user");

    private static final String allAccessUser = "admin_all_access";
    private static final Header allAccessUserHeader = encodeBasicHeader(allAccessUser, allAccessUser);
    @Before
    public void setupSettingsIndexPattern() throws Exception {
        Settings settings = Settings.builder()
                .put("plugins.security.system_indices.indices", ".testSystemExtensionIndex")
                .put("plugins.security.system_indices.enabled", true)
                .build();

        setup(Settings.EMPTY,
                new DynamicSecurityConfig()
                        .setSecurityRoles("roles_system_indices.yml")
                        .setSecurityInternalUsers("internal_users_system_indices.yml")
                        .setSecurityRolesMapping("roles_mapping_system_indices.yml"),

                //                        .setSecurityRoles("roles_index_patterns.yml")
                //                        .setSecurityInternalUsers("internal_users_index_patterns.yml")
                //                        .setSecurityRolesMapping("roles_mapping_index_patterns.yml"),
                settings,
                true);
    }

    @Test
    public void testNegativeLookaheadPattern() throws Exception {

        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse response = rh.executeGetRequest( "*/_search", NegativeLookaheadUserHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executeGetRequest( "r*/_search", NegativeLookaheadUserHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testRegexPattern() throws Exception {
        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse response = rh.executeGetRequest( "*/_search", NegatedRegexUserHeader);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        response = rh.executeGetRequest( "r*/_search", NegatedRegexUserHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testExtensionIndexAccessShouldSuccedForExtensionUser() throws Exception {
        RestHelper rh = nonSslRestHelper();

        String indexSettings = "{\n" +
                "    \"index\" : {\n" +
                "        \"refresh_interval\" : null\n" +
                "    }\n" +
                "}";

        //as super-admin

        RestHelper.HttpResponse response = rh.executePutRequest(".testSystemExtensionIndex" + "/_settings", indexSettings, allAccessUserHeader);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());


        response = rh.executeGetRequest( ".testSystemExtensionIndex", NegatedRegexUserHeader);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    public void testExtensionIndexAccessShouldFailForCommonUserEvenWithStarPermission() throws Exception {
        RestHelper rh = nonSslRestHelper();
        RestHelper.HttpResponse response = rh.executeGetRequest( ".testSystemExtensionIndex", NegativeLookaheadUserHeader);
        Assert.assertNotEquals(HttpStatus.SC_OK, response.getStatusCode());

    }
}
