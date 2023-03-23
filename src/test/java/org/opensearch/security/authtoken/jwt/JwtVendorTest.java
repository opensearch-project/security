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

import java.util.Map;

import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

public class JwtVendorTest {

    @Test
    public void testCreateJwkFromSettings() throws Exception {
        Settings settings = Settings.builder()
                .put("signing_key", "abc123").build();

        JsonWebKey jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("HS512", jwk.getAlgorithm());
        Assert.assertEquals("sig", jwk.getPublicKeyUse().toString());
        Assert.assertEquals("abc123", jwk.getProperty("k"));
        System.out.print(jwk.getPublicKeyUse());
    }

    @Test (expected = Exception.class)
    public void testCreateJwkFromSettingsWithoutSigningKey() throws Exception{
        Settings settings = Settings.builder()
                .put("jwt", "").build();
        JwtVendor.createJwkFromSettings(settings);
    }

    @Test
    public void testCreateJwt() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "extension_0";
        Integer expiryMin = 5;
        Settings settings =  Settings.builder().put("signing_key", "abc123").build();

        JwtVendor jwtVendor = new JwtVendor(settings);
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expiryMin);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
    }

    @Test (expected = Exception.class)
    public void testCreateJwtWithBadExpiry() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "extension_0";
        Integer expiryMin = -1;

        Settings settings =  Settings.builder().put("signing_key", "abc123").build();
        JwtVendor jwtVendor = new JwtVendor(settings);

        jwtVendor.createJwt(issuer, subject, audience, expiryMin);
    }
}
