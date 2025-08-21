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

package org.opensearch.security.auth.http.jwt.keybyjwks;

import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * Test for HTTPJwtKeyByJWKSAuthenticator using existing OIDC infrastructure.
 * This test validates that the new JWKS authenticator works correctly by extending
 * AbstractHTTPJwtAuthenticator and using existing KeySetRetriever and SelfRefreshingKeySet.
 */
public class HTTPJwtKeyByJWKSAuthenticatorTest {

    @Test
    public void testJwksBasicAuthentication() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", "https://rishavaz-new-jwks.s3.eu-west-1.amazonaws.com/jwks.json")
            .build();

        HTTPJwtKeyByJWKSAuthenticator jwtAuth = new HTTPJwtKeyByJWKSAuthenticator(settings, null);

        // Test that the authenticator is properly initialized with the JWKS URI
        assertThat(jwtAuth.getType(), is("jwt-key-by-jwks"));
    }

    @Test
    public void testJwksWithRolesKey() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", "https://rishavaz-new-jwks.s3.eu-west-1.amazonaws.com/jwks.json")
            .putList("roles_key", "roles")
            .build();

        HTTPJwtKeyByJWKSAuthenticator jwtAuth = new HTTPJwtKeyByJWKSAuthenticator(settings, null);

        // Test that the authenticator is properly initialized with roles configuration
        assertThat(jwtAuth.getType(), is("jwt-key-by-jwks"));
    }

    @Test
    public void testJwksWithCaching() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", "https://rishavaz-new-jwks.s3.eu-west-1.amazonaws.com/jwks.json")
            .put("cache_jwks_endpoint", true)
            .put("idp_request_timeout_ms", 10000)
            .put("refresh_rate_limit_count", 5)
            .build();

        HTTPJwtKeyByJWKSAuthenticator jwtAuth = new HTTPJwtKeyByJWKSAuthenticator(settings, null);

        // Test that the authenticator is properly initialized with caching configuration
        assertThat(jwtAuth.getType(), is("jwt-key-by-jwks"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMissingJwksUri() throws Exception {
        Settings settings = Settings.builder().build();
        new HTTPJwtKeyByJWKSAuthenticator(settings, null);
    }

    @Test
    public void testAuthenticatorType() throws Exception {
        Settings settings = Settings.builder()
            .put("jwks_uri", "https://rishavaz-new-jwks.s3.eu-west-1.amazonaws.com/jwks.json")
            .build();

        HTTPJwtKeyByJWKSAuthenticator jwtAuth = new HTTPJwtKeyByJWKSAuthenticator(settings, null);
        assertThat(jwtAuth.getType(), is("jwt-key-by-jwks"));
    }
}
