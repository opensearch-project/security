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

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.support.SecurityJsonNode;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class RoleBasedAccessTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public RoleBasedAccessTest() {
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testActionGroupsApi() throws Exception {

        setupWithRestRoles();

        rh.sendAdminCertificate = false;

        // worf and sarek have access, worf has some endpoints disabled

        // ------ GET ------

        // --- Allowed Access ---

        // legacy user API, accessible for worf, single user
        HttpResponse response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertTrue(settings.get("admin.hash") != null);
        assertThat(settings.get("admin.hash"), is(""));

        // new user API, accessible for worf, single user
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertTrue(settings.get("admin.hash") != null);

        // legacy user API, accessible for worf, get complete config
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(settings.get("admin.hash"), is(""));
        assertThat(settings.get("sarek.hash"), is(""));
        assertThat(settings.get("worf.hash"), is(""));

        // new user API, accessible for worf
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(settings.get("admin.hash"), is(""));
        assertThat(settings.get("sarek.hash"), is(""));
        assertThat(settings.get("worf.hash"), is(""));

        // legacy user API, accessible for worf, get complete config, no trailing slash
        response = rh.executeGetRequest(ENDPOINT + "/internalusers", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(settings.get("admin.hash"), is(""));
        assertThat(settings.get("sarek.hash"), is(""));
        assertThat(settings.get("worf.hash"), is(""));

        // new user API, accessible for worf, get complete config, no trailing slash
        response = rh.executeGetRequest(ENDPOINT + "/internalusers", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(settings.get("admin.hash"), is(""));
        assertThat(settings.get("sarek.hash"), is(""));
        assertThat(settings.get("worf.hash"), is(""));

        // roles API, GET accessible for worf
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat("", "nagilum", is(settings.getAsList("opendistro_security_all_access.users").get(0)));
        assertThat("", "starfleet*", is(settings.getAsList("opendistro_security_role_starfleet_library.backend_roles").get(0)));
        assertThat("", "bug108", is(settings.getAsList("opendistro_security_zdummy_all.users").get(0)));

        // Deprecated get configuration API, acessible for sarek
        // response = rh.executeGetRequest("_opendistro/_security/api/configuration/internalusers", encodeBasicHeader("sarek", "sarek"));
        // settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        // assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        // assertThat(settings.get("admin.hash"), is(""));
        // assertThat(settings.get("sarek.hash"), is(""));
        // assertThat(settings.get("worf.hash"), is(""));

        // Deprecated get configuration API, acessible for sarek
        // response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("sarek", "sarek"));
        // settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        // assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        // assertThat("indices:*", is("", settings.getAsList("ALL").get(0)));
        // assertThat("cluster:monitor/*", is("", settings.getAsList("OPENDISTRO_SECURITY_CLUSTER_MONITOR").get(0)));
        // new format for action groups
        // assertThat("READ_UT", is("", settings.getAsList("CRUD.permissions").get(0)));

        // configuration API, not accessible for worf
        // response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("worf", "worf"));
        // assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        // Assert.assertTrue(response.getBody().contains("does not have any access to endpoint CONFIGURATION"));

        // cache API, not accessible for worf since it's disabled globally
        response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        Assert.assertTrue(response.getBody().contains("does not have any access to endpoint CACHE"));

        // cache API, not accessible for sarek since it's disabled globally
        response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("sarek", "sarek"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        Assert.assertTrue(response.getBody().contains("does not have any access to endpoint CACHE"));

        // Admin user has no eligible role at all
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("admin", "admin"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

        // Admin user has no eligible role at all
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("admin", "admin"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

        // Admin user has no eligible role at all
        response = rh.executeGetRequest(ENDPOINT + "/internalusers", encodeBasicHeader("admin", "admin"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

        // Admin user has no eligible role at all
        response = rh.executeGetRequest(ENDPOINT + "/roles", encodeBasicHeader("admin", "admin"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

        // --- DELETE ---

        // Admin user has no eligible role at all
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("admin", "admin"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));
        Assert.assertTrue(response.getBody().contains("does not have any role privileged for admin access"));

        // Worf, has access to internalusers API, able to delete
        response = rh.executeDeleteRequest(ENDPOINT + "/internalusers/other", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("'other' deleted"));

        // Worf, has access to internalusers API, user "other" deleted now
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/other", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
        Assert.assertTrue(response.getBody().contains("'other' not found"));

        // Worf, has access to roles API, get captains role
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(
            response.findArrayInJson("opendistro_security_role_starfleet_captains.cluster_permissions"),
            allOf(hasItem("*bulk*"), hasItem("cluster:monitor*"))
        );

        // Worf, has access to roles API, able to delete
        response = rh.executeDeleteRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            encodeBasicHeader("worf", "worf")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("'opendistro_security_role_starfleet_captains' deleted"));

        // Worf, has access to roles API, captains role deleted now
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));
        Assert.assertTrue(response.getBody().contains("'opendistro_security_role_starfleet_captains' not found"));

        // Worf, has no DELETE access to rolemappings API
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_unittest_1", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // Worf, has no DELETE access to rolemappings API, legacy endpoint
        response = rh.executeDeleteRequest(ENDPOINT + "/rolesmapping/opendistro_security_unittest_1", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // --- PUT ---

        // admin, no access
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_tenants.json"),
            encodeBasicHeader("admin", "admin")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // worf, restore role starfleet captains
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_different_content.json"),
            encodeBasicHeader("worf", "worf")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_CREATED));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();

        // starfleet role present again
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("worf", "worf"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        assertThat(
            new SecurityJsonNode(DefaultObjectMapper.readTree(response.getBody())).getDotted(
                "opendistro_security_role_starfleet_captains.index_permissions"
            ).get(0).get("allowed_actions").get(0).asString(),
            is("blafasel")
        );

        // Try the same, but now with admin certificate
        rh.sendAdminCertificate = true;

        // admin
        response = rh.executeGetRequest(ENDPOINT + "/internalusers/admin", encodeBasicHeader("la", "lu"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertTrue(settings.get("admin.hash") != null);
        assertThat(settings.get("admin.hash"), is(""));

        // worf and config
        // response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("bla", "fasel"));
        // assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // cache
        response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("wrong", "wrong"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // -- test user, does not have any endpoints disabled, but has access to API, i.e. full access

        rh.sendAdminCertificate = false;

        // GET actiongroups
        // response = rh.executeGetRequest("_opendistro/_security/api/configuration/actiongroups", encodeBasicHeader("test", "test"));
        // assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        response = rh.executeGetRequest("_opendistro/_security/api/actiongroups", encodeBasicHeader("test", "test"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // clear cache - globally disabled, has to fail
        response = rh.executeDeleteRequest("_opendistro/_security/api/cache", encodeBasicHeader("test", "test"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_FORBIDDEN));

        // PUT roles
        response = rh.executePutRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            FileHelper.loadFile("restapi/roles_captains_different_content.json"),
            encodeBasicHeader("test", "test")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // GET captions role
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("test", "test"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));

        // Delete captions role
        response = rh.executeDeleteRequest(
            ENDPOINT + "/roles/opendistro_security_role_starfleet_captains",
            encodeBasicHeader("test", "test")
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertTrue(response.getBody().contains("'opendistro_security_role_starfleet_captains' deleted"));

        // GET captions role
        response = rh.executeGetRequest(ENDPOINT + "/roles/opendistro_security_role_starfleet_captains", encodeBasicHeader("test", "test"));
        assertThat(response.getStatusCode(), is(HttpStatus.SC_NOT_FOUND));

    }
}
