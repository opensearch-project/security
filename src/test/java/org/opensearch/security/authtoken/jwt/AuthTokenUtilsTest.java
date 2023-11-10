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

package org.opensearch.security.authtoken.jwt;

import java.util.Collections;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.util.AuthTokenUtils;
import org.opensearch.test.rest.FakeRestRequest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AuthTokenUtilsTest {

    @Test
    public void testIsAccessToRestrictedEndpointsForOnBehalfOfToken() {
        NamedXContentRegistry namedXContentRegistry = new NamedXContentRegistry(Collections.emptyList());

        FakeRestRequest request = new FakeRestRequest.Builder(namedXContentRegistry).withPath("/api/generateonbehalfoftoken")
            .withMethod(RestRequest.Method.POST)
            .build();

        assertTrue(AuthTokenUtils.isAccessToRestrictedEndpoints(SecurityRequestFactory.from(request), "api/generateonbehalfoftoken"));
    }

    @Test
    public void testIsAccessToRestrictedEndpointsForAccount() {
        NamedXContentRegistry namedXContentRegistry = new NamedXContentRegistry(Collections.emptyList());

        FakeRestRequest request = new FakeRestRequest.Builder(namedXContentRegistry).withPath("/api/account")
            .withMethod(RestRequest.Method.PUT)
            .build();

        assertTrue(AuthTokenUtils.isAccessToRestrictedEndpoints(SecurityRequestFactory.from(request), "api/account"));
    }

    @Test
    public void testIsAccessToRestrictedEndpointsFalseCase() {
        NamedXContentRegistry namedXContentRegistry = new NamedXContentRegistry(Collections.emptyList());

        FakeRestRequest request = new FakeRestRequest.Builder(namedXContentRegistry).withPath("/api/someotherendpoint")
            .withMethod(RestRequest.Method.GET)
            .build();

        assertFalse(AuthTokenUtils.isAccessToRestrictedEndpoints(SecurityRequestFactory.from(request), "api/someotherendpoint"));
    }

    @Test
    public void testIsKeyNullWithNullValue() {
        Settings settings = Settings.builder().put("someKey", (String) null).build();
        assertTrue(AuthTokenUtils.isKeyNull(settings, "someKey"));
    }

    @Test
    public void testIsKeyNullWithNonNullValue() {
        Settings settings = Settings.builder().put("someKey", "value").build();
        assertFalse(AuthTokenUtils.isKeyNull(settings, "someKey"));
    }

    @Test
    public void testIsKeyNullWithAbsentKey() {
        Settings settings = Settings.builder().build();
        assertTrue(AuthTokenUtils.isKeyNull(settings, "absentKey"));
    }
}
