/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http:/www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.cache;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;

public class CachingTest extends SingleClusterTest{

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
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        System.out.println(res.getBody());
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
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
        System.out.println(res.getBody());
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
        HttpResponse res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty", new BasicHeader("opendistro_security_impersonate_as", "impuser"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty", new BasicHeader("opendistro_security_impersonate_as", "impuser"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty", new BasicHeader("opendistro_security_impersonate_as", "impuser"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());
        res = rh.executeGetRequest("_opendistro/_security/authinfo?pretty", new BasicHeader("opendistro_security_impersonate_as", "impuser2"));
        System.out.println(res.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        Assert.assertEquals(4, DummyHTTPAuthenticator.getCount());
        Assert.assertEquals(3, DummyAuthorizer.getCount());
        Assert.assertEquals(4, DummyAuthenticationBackend.getAuthCount());
        Assert.assertEquals(2, DummyAuthenticationBackend.getExistsCount());

    }

}
