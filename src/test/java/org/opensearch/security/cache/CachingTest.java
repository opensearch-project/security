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

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

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
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        Assert.assertEquals(3, DummyHTTPAuthenticator.getCount());
        Assert.assertEquals(1, DummyAuthorizer.getCount());
        Assert.assertEquals(3, DummyAuthenticationBackend.getAuthCount());
        Assert.assertEquals(0, DummyAuthenticationBackend.getExistsCount());
    }

    @Test
    public void testRestNoCaching() throws Exception {
        final Settings settings = Settings.builder().put("plugins.security.cache.ttl_minutes", 0).build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);
        final RestHelper rh = nonSslRestHelper();
        HttpResponse res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        Assert.assertEquals(3, DummyHTTPAuthenticator.getCount());
        Assert.assertEquals(3, DummyAuthorizer.getCount());
        Assert.assertEquals(3, DummyAuthenticationBackend.getAuthCount());
        Assert.assertEquals(0, DummyAuthenticationBackend.getExistsCount());
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
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest(
            "_opendistro/_security/authinfo?pretty",
            new BasicHeader("opendistro_security_impersonate_as", "impuser")
        );
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest(
            "_opendistro/_security/authinfo?pretty",
            new BasicHeader("opendistro_security_impersonate_as", "impuser")
        );
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest(
            "_opendistro/_security/authinfo?pretty",
            new BasicHeader("opendistro_security_impersonate_as", "impuser2")
        );
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        Assert.assertEquals(4, DummyHTTPAuthenticator.getCount());
        Assert.assertEquals(3, DummyAuthorizer.getCount());
        Assert.assertEquals(4, DummyAuthenticationBackend.getAuthCount());
        Assert.assertEquals(2, DummyAuthenticationBackend.getExistsCount());
    }
}
