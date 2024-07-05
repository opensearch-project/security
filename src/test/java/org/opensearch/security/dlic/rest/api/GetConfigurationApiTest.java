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

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;

public class GetConfigurationApiTest extends AbstractRestApiUnitTest {
    private final String ENDPOINT;

    protected String getEndpointPrefix() {
        return PLUGINS_PREFIX;
    }

    public GetConfigurationApiTest() {
        ENDPOINT = getEndpointPrefix() + "/api";
    }

    @Test
    public void testGetConfiguration() throws Exception {

        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // wrong config name -> bad request
        HttpResponse response = null;

        // test that every config is accessible
        // config
        response = rh.executeGetRequest(ENDPOINT + "/securityconfig");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(true, is(settings.getAsBoolean("config.dynamic.authc.authentication_domain_basic_internal.http_enabled", false)));
        Assert.assertNull(settings.get("_opendistro_security_meta.type"));

        // internalusers
        response = rh.executeGetRequest(ENDPOINT + "/internalusers");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat(settings.get("admin.hash"), is(""));
        assertThat(settings.get("other.hash"), is(""));
        Assert.assertNull(settings.get("_opendistro_security_meta.type"));

        // roles
        response = rh.executeGetRequest(ENDPOINT + "/roles");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        JsonNode jnode = DefaultObjectMapper.readTree(response.getBody());
        assertThat("cluster:*", is(jnode.get("opendistro_security_all_access").get("cluster_permissions").get(0).asText()));
        Assert.assertNull(settings.get("_opendistro_security_meta.type"));

        // roles
        response = rh.executeGetRequest(ENDPOINT + "/rolesmapping");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat("starfleet", is(settings.getAsList("opendistro_security_role_starfleet.backend_roles").get(0)));
        Assert.assertNull(settings.get("_opendistro_security_meta.type"));

        // action groups
        response = rh.executeGetRequest(ENDPOINT + "/actiongroups");
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        assertThat("indices:*", is(settings.getAsList("ALL.allowed_actions").get(0)));
        Assert.assertTrue(settings.hasValue("INTERNAL.allowed_actions"));
        Assert.assertNull(settings.get("_opendistro_security_meta.type"));
    }

}
