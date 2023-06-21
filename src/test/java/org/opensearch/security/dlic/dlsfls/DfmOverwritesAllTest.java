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

package org.opensearch.security.dlic.dlsfls;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

/**
 * Tests that the dfm_empty_overwrites_all flag works correctly.
 * Per default, if a user has a role that adds restrictions to an index
 * regarding DLS, FLS or masked fields (DFM), and another role that has no restrictions
 * on the same index, the restrictions from the first role still applies.
 *
 * If the dfm_empty_overwrites_all flag is set to true, the logic is reversed:
 * If a user has a role that places no restrictions on an index, this trumps
 * all other role that eventually do place restrictions on this index.
 */
public class DfmOverwritesAllTest extends AbstractDlsFlsTest {

    protected void populateData(Client tc) {

        tc.index(
            new IndexRequest("index1-1").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"field1\": 1, \"field2\": \"value-2-1\", \"field3\": \"value-3-1\", \"field4\": \"value-4-1\" }",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest("index1-2").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"field1\": 2, \"field2\": \"value-2-2\", \"field3\": \"value-3-2\", \"field4\": \"value-4-2\" }",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest("index1-3").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"field1\": 3, \"field2\": \"value-2-3\", \"field3\": \"value-3-3\", \"field4\": \"value-4-3\" }",
                    XContentType.JSON
                )
        ).actionGet();

        tc.index(
            new IndexRequest("index1-4").id("0")
                .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source(
                    "{\"field1\": 4, \"field2\": \"value-2-4\", \"field3\": \"value-3-4\", \"field4\": \"value-4-4\" }",
                    XContentType.JSON
                )
        ).actionGet();

    }

    /**
     * Admin user sees all, no dfm restrictions apply.
     * @throws Exception
     */
    @Test
    public void testDFMUnrestrictedUser() throws Exception {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_DFM_EMPTY_OVERRIDES_ALL, true).build();

        setup(
            settings,
            new DynamicSecurityConfig().setConfig("securityconfig_dfm_empty_overwrites_all.yml")
                .setSecurityInternalUsers("internal_users_dfm_empty_overwrites_all.yml")
                .setSecurityRoles("roles_dfm_empty_overwrites_all.yml")
                .setSecurityRolesMapping("rolesmapping_dfm_empty_overwrites_all.yml")
        );

        HttpResponse response;

        response = rh.executeGetRequest("/index1-*/_search?pretty", encodeBasicHeader("admin", "password"));
        Assert.assertEquals(200, response.getStatusCode());

        // the only document in index1-1 is filtered by DLS query, so normally no hit in index-1-1
        Assert.assertTrue(response.getBody().contains("index1-1"));

        // field3 and field4 - normally filtered out by FLS
        Assert.assertTrue(response.getBody().contains("value-3-1"));
        Assert.assertTrue(response.getBody().contains("value-4-1"));
        Assert.assertTrue(response.getBody().contains("value-3-2"));
        Assert.assertTrue(response.getBody().contains("value-4-2"));
        Assert.assertTrue(response.getBody().contains("value-3-3"));
        Assert.assertTrue(response.getBody().contains("value-4-3"));
        Assert.assertTrue(response.getBody().contains("value-3-4"));
        Assert.assertTrue(response.getBody().contains("value-4-4"));

        // field2 - normally masked
        Assert.assertTrue(response.getBody().contains("value-2-1"));
        Assert.assertTrue(response.getBody().contains("value-2-2"));
        Assert.assertTrue(response.getBody().contains("value-2-3"));
        Assert.assertTrue(response.getBody().contains("value-2-4"));
    }

    /**
     * Tests that the DFM settings are applied. User has only one role
     * with D/F/M all enabled, so restrictions must kick in.
     * @throws Exception
     */
    @Test
    public void testDFMRestrictedUser() throws Exception {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_DFM_EMPTY_OVERRIDES_ALL, true).build();

        setup(
            settings,
            new DynamicSecurityConfig().setConfig("securityconfig_dfm_empty_overwrites_all.yml")
                .setSecurityInternalUsers("internal_users_dfm_empty_overwrites_all.yml")
                .setSecurityRoles("roles_dfm_empty_overwrites_all.yml")
                .setSecurityRolesMapping("rolesmapping_dfm_empty_overwrites_all.yml")
        );

        HttpResponse response;

        response = rh.executeGetRequest("/index1-*/_search?pretty", encodeBasicHeader("dfm_restricted_role", "password"));
        Assert.assertEquals(200, response.getStatusCode());

        // the only document in index1-1 is filtered by DLS query, so no hit in index-1-1
        Assert.assertFalse(response.getBody().contains("index1-1"));

        // field3 and field4 - filtered out by FLS
        Assert.assertFalse(response.getBody().contains("value-3-1"));
        Assert.assertFalse(response.getBody().contains("value-4-1"));
        Assert.assertFalse(response.getBody().contains("value-3-2"));
        Assert.assertFalse(response.getBody().contains("value-4-2"));
        Assert.assertFalse(response.getBody().contains("value-3-3"));
        Assert.assertFalse(response.getBody().contains("value-4-3"));
        Assert.assertFalse(response.getBody().contains("value-3-4"));
        Assert.assertFalse(response.getBody().contains("value-4-4"));

        // field2 - masked
        Assert.assertFalse(response.getBody().contains("value-2-1"));
        Assert.assertFalse(response.getBody().contains("value-2-2"));
        Assert.assertFalse(response.getBody().contains("value-2-3"));
        Assert.assertFalse(response.getBody().contains("value-2-4"));

        // field2 - check also some masked values
        Assert.assertTrue(response.getBody().contains("514b27191e2322b0f7cd6afc3a5d657ff438fd0cc8dc229bd1a589804fdffd99"));
        Assert.assertTrue(response.getBody().contains("3090f7e867f390fb96b20ba30ee518b09a927b857393ebd1262f31191a385efa"));
    }

    /**
     * User has the restricted role as in test testDFMRestrictedUser(). In addition, user has
     * another role with the same index pattern as the restricted role but no DFM settings. In that
     * case the unrestricted role should trump the restricted one, so basically user has
     * full access again.
     * @throws Exception
     */
    @Test
    public void testDFMRestrictedAndUnrestrictedAllIndices() throws Exception {

        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_DFM_EMPTY_OVERRIDES_ALL, true).build();

        setup(
            settings,
            new DynamicSecurityConfig().setConfig("securityconfig_dfm_empty_overwrites_all.yml")
                .setSecurityInternalUsers("internal_users_dfm_empty_overwrites_all.yml")
                .setSecurityRoles("roles_dfm_empty_overwrites_all.yml")
                .setSecurityRolesMapping("rolesmapping_dfm_empty_overwrites_all.yml")
        );

        HttpResponse response;

        response = rh.executeGetRequest(
            "/index1-*/_search?pretty",
            encodeBasicHeader("dfm_restricted_and_unrestricted_all_indices_role", "password")
        );
        Assert.assertEquals(200, response.getStatusCode());

        // the only document in index1-1 is filtered by DLS query, so normally no hit in index-1-1
        Assert.assertTrue(response.getBody().contains("index1-1"));

        // field3 and field4 - normally filtered out by FLS
        Assert.assertTrue(response.getBody().contains("value-3-1"));
        Assert.assertTrue(response.getBody().contains("value-4-1"));
        Assert.assertTrue(response.getBody().contains("value-3-2"));
        Assert.assertTrue(response.getBody().contains("value-4-2"));
        Assert.assertTrue(response.getBody().contains("value-3-3"));
        Assert.assertTrue(response.getBody().contains("value-4-3"));
        Assert.assertTrue(response.getBody().contains("value-3-4"));
        Assert.assertTrue(response.getBody().contains("value-4-4"));

        // field2 - normally masked
        Assert.assertTrue(response.getBody().contains("value-2-1"));
        Assert.assertTrue(response.getBody().contains("value-2-2"));
        Assert.assertTrue(response.getBody().contains("value-2-3"));
        Assert.assertTrue(response.getBody().contains("value-2-4"));
    }

    /**
     * User has the restricted role as in test testDFMRestrictedUser(). In addition, user has
     * another role where the index pattern matches two specific index ("index1-2", "index-1-1"), means this role has two indices
     * which are more specific than the index pattern in the restricted role ("index1-*"), So the second role should
     * remove the DMF restrictions from exactly two indices. Otherwise, restrictions still apply.
     * @throws Exception
     */
    @Test
    public void testDFMRestrictedAndUnrestrictedOneIndex() throws Exception {
        final Settings settings = Settings.builder().put(ConfigConstants.SECURITY_DFM_EMPTY_OVERRIDES_ALL, true).build();
        setup(
            settings,
            new DynamicSecurityConfig().setConfig("securityconfig_dfm_empty_overwrites_all.yml")
                .setSecurityInternalUsers("internal_users_dfm_empty_overwrites_all.yml")
                .setSecurityRoles("roles_dfm_empty_overwrites_all.yml")
                .setSecurityRolesMapping("rolesmapping_dfm_empty_overwrites_all.yml")
        );

        HttpResponse response;

        response = rh.executeGetRequest(
            "/_plugins/_security/authinfo?pretty",
            encodeBasicHeader("dfm_restricted_and_unrestricted_one_index_role", "password")
        );

        response = rh.executeGetRequest(
            "/index1-*/_search?pretty",
            encodeBasicHeader("dfm_restricted_and_unrestricted_one_index_role", "password")
        );
        Assert.assertEquals(200, response.getStatusCode());

        // we have a role that places no restrictions on index-1-1, lifting the DLS from the restricted role
        Assert.assertTrue(response.getBody().contains("index1-1"));
        Assert.assertTrue(response.getBody().contains("value-2-1"));
        Assert.assertTrue(response.getBody().contains("value-3-1"));
        Assert.assertTrue(response.getBody().contains("value-4-1"));

        // field3 and field4 - normally filtered out by FLS. The second role
        // lifts restrictions for index1-1 and index1-4, so only those
        // values should be visible for index1-1 and index1-4
        Assert.assertTrue(response.getBody().contains("value-3-1"));
        Assert.assertTrue(response.getBody().contains("value-4-1"));
        Assert.assertTrue(response.getBody().contains("value-3-4"));
        Assert.assertTrue(response.getBody().contains("value-4-4"));

        // FLS restrictions still in place for index1-2 and index1-3, those
        // fields must not be present
        Assert.assertFalse(response.getBody().contains("value-3-2"));
        Assert.assertFalse(response.getBody().contains("value-4-2"));
        Assert.assertFalse(response.getBody().contains("value-3-3"));
        Assert.assertFalse(response.getBody().contains("value-4-3"));

        // field2 - normally masked, but for index1-1 and index1-4 restrictions are
        // lifted by second role, so we have cleartext in index1-1 and index1-4
        Assert.assertTrue(response.getBody().contains("value-2-1"));
        Assert.assertTrue(response.getBody().contains("value-2-4"));

        // but we still have masked values for index1-2 and index1-3
        Assert.assertTrue(response.getBody().contains("514b27191e2322b0f7cd6afc3a5d657ff438fd0cc8dc229bd1a589804fdffd99"));
        Assert.assertTrue(response.getBody().contains("3090f7e867f390fb96b20ba30ee518b09a927b857393ebd1262f31191a385efa"));
    }
}
