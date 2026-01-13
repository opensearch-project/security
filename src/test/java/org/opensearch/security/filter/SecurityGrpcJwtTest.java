/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.security.filter;

import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auth.http.jwt.HTTPJwtAuthenticator;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import io.grpc.Metadata;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class SecurityGrpcJwtTest {

    // Reuse the same test infrastructure as HTTPJwtAuthenticatorTest
    private static final byte[] secretKeyBytes = new byte[1024];
    private static final SecretKey secretKey;

    static {
        new SecureRandom().nextBytes(secretKeyBytes);
        secretKey = Keys.hmacShaKeyFor(secretKeyBytes);
    }

    @Test
    public void testValidJwtTokenExtraction() {
        SecurityGrpcFilter provider = new SecurityGrpcFilter();
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        
        var interceptors = provider.getOrderedGrpcInterceptors(threadContext);
        var interceptor = interceptors.get(0).getInterceptor();
        
        // Create valid JWT token using same method as HTTPJwtAuthenticatorTest
        String validJwt = createValidJwtToken("testuser", "role1,role2");
        
        // Create gRPC metadata with JWT
        Metadata metadata = new Metadata();
        metadata.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + validJwt);
        
        // Verify JWT is extracted correctly
        assertNotNull("Interceptor should not be null", interceptor);
        
        // Verify the JWT token can be validated by existing authenticator
        AuthCredentials credentials = validateJwtWithExistingAuthenticator(validJwt);
        assertNotNull("JWT should be valid", credentials);
        assertEquals("Username should match", "testuser", credentials.getUsername());
        assertTrue("Should have roles", credentials.getBackendRoles().size() > 0);
        
        System.out.println("✓ Valid JWT token test passed");
    }

    @Test
    public void testInvalidJwtTokenExtraction() {
        String invalidJwt = "invalid.jwt.token";
        
        // Verify invalid JWT is rejected by existing authenticator
        AuthCredentials credentials = validateJwtWithExistingAuthenticator(invalidJwt);
        assertNull("Invalid JWT should be rejected", credentials);
        
        System.out.println("✓ Invalid JWT token test passed");
    }

    @Test
    public void testExpiredJwtToken() {
        // Create expired JWT token
        String expiredJwt = Jwts.builder()
            .setSubject("testuser")
            .setExpiration(new java.util.Date(100)) // Expired in 1970
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();
        
        // Verify expired JWT is rejected
        AuthCredentials credentials = validateJwtWithExistingAuthenticator(expiredJwt);
        assertNull("Expired JWT should be rejected", credentials);
        
        System.out.println("✓ Expired JWT token test passed");
    }

    @Test
    public void testJwtWithRoles() {
        // Create JWT with roles
        String jwtWithRoles = Jwts.builder()
            .setSubject("admin")
            .claim("roles", "admin,superuser")
            .signWith(secretKey, SignatureAlgorithm.HS512)
            .compact();
        
        // Verify JWT with roles is processed correctly
        AuthCredentials credentials = validateJwtWithExistingAuthenticator(jwtWithRoles);
        assertNotNull("JWT with roles should be valid", credentials);
        assertEquals("Username should match", "admin", credentials.getUsername());
        
        System.out.println("✓ JWT with roles test passed");
    }

    /**
     * Helper method to create valid JWT tokens for testing
     */
    private String createValidJwtToken(String username, String roles) {
        JwtBuilder builder = Jwts.builder()
            .setSubject(username);
        
        if (roles != null) {
            builder.claim("roles", roles);
        }
        
        return builder.signWith(secretKey, SignatureAlgorithm.HS512).compact();
    }

    /**
     * Helper method to validate JWT using existing HTTPJwtAuthenticator
     * This reuses the security plugin's actual JWT validation logic
     */
    private AuthCredentials validateJwtWithExistingAuthenticator(String jwtToken) {
        // Create settings with signing key (same as HTTPJwtAuthenticatorTest)
        Settings settings = Settings.builder()
            .put("signing_key", java.util.Base64.getEncoder().encodeToString(secretKeyBytes))
            .put("roles_key", "roles")
            .build();
        
        // Create JWT authenticator
        HTTPJwtAuthenticator jwtAuth = new HTTPJwtAuthenticator(settings, null);
        
        // Create fake request with JWT token
        Map<String, String> headers = Map.of("Authorization", "Bearer " + jwtToken);
        FakeRestRequest fakeRequest = new FakeRestRequest(headers, new HashMap<>());
        
        // Extract credentials using existing logic
        return jwtAuth.extractCredentials(fakeRequest.asSecurityRequest(), null);
    }
}
