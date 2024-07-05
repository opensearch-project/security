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

package org.opensearch.security.cache;

import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class CachingTest extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "cache";
    }

    @Before
    public void reset() {
        DummyHTTPAuthenticator.reset();
        DummyAuthorizer.reset();
        DummyAuthenticationBackend.reset();

    }

    @Test
    public void testRestCaching() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();
        HttpResponse res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        assertThat(DummyHTTPAuthenticator.getCount(), is(3L));
        assertThat(DummyAuthorizer.getCount(), is(1L));
        assertThat(DummyAuthenticationBackend.getAuthCount(), is(3L));
        assertThat(DummyAuthenticationBackend.getExistsCount(), is(0L));
    }

    @Test
    public void testRestNoCaching() throws Exception {
        final Settings settings = Settings.builder().put("plugins.security.cache.ttl_minutes", 0).build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);
        final RestHelper rh = nonSslRestHelper();
        HttpResponse res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        assertThat(DummyHTTPAuthenticator.getCount(), is(3L));
        assertThat(DummyAuthorizer.getCount(), is(3L));
        assertThat(DummyAuthenticationBackend.getAuthCount(), is(3L));
        assertThat(DummyAuthenticationBackend.getExistsCount(), is(0L));
    }

    @Test
    public void testRestCachingWithImpersonation() throws Exception {
        final Settings settings = Settings.builder().putList("plugins.security.authcz.rest_impersonation_user.dummy", "*").build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);
        final RestHelper rh = nonSslRestHelper();
        HttpResponse res = rh.executeGetRequest(
            "_opendistro/_security/authinfo?pretty",
            new BasicHeader("opendistro_security_impersonate_as", "impuser")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest(
            "_opendistro/_security/authinfo?pretty",
            new BasicHeader("opendistro_security_impersonate_as", "impuser")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest(
            "_opendistro/_security/authinfo?pretty",
            new BasicHeader("opendistro_security_impersonate_as", "impuser")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));
        res = rh.executeGetRequest(
            "_opendistro/_security/authinfo?pretty",
            new BasicHeader("opendistro_security_impersonate_as", "impuser2")
        );
        assertThat(res.getStatusCode(), is(HttpStatus.SC_OK));

        assertThat(DummyHTTPAuthenticator.getCount(), is(4L));
        assertThat(DummyAuthorizer.getCount(), is(3L));
        assertThat(DummyAuthenticationBackend.getAuthCount(), is(4L));
        assertThat(DummyAuthenticationBackend.getExistsCount(), is(2L));
    }
}
