/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.http;

import java.security.PrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;

import io.jsonwebtoken.Jwts;

import static java.util.Objects.requireNonNull;
import static io.jsonwebtoken.SignatureAlgorithm.RS256;

class JwtAuthorizationHeaderFactory {
    public static final String AUDIENCE = "OpenSearch";
    public static final String ISSUER = "test-code";
    private final PrivateKey privateKey;

    private final List<String> usernameClaimName;

    private final List<String> rolesClaimName;

    private final String headerName;

    public JwtAuthorizationHeaderFactory(
        PrivateKey privateKey,
        List<String> usernameClaimName,
        List<String> rolesClaimName,
        String headerName
    ) {
        this.privateKey = requireNonNull(privateKey, "Private key is required");
        this.usernameClaimName = requireNonNull(usernameClaimName, "Username claim name is required");
        this.rolesClaimName = requireNonNull(rolesClaimName, "Roles claim name is required.");
        this.headerName = requireNonNull(headerName, "Header name is required");
    }

    Header generateValidToken(String username, String... roles) {
        requireNonNull(username, "Username is required");
        Date now = new Date();
        String token = Jwts.builder()
            .setClaims(customClaimsMap(username, roles))
            .setIssuer(ISSUER)
            .setSubject(subject(username))
            .setAudience(AUDIENCE)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(privateKey, RS256)
            .compact();
        return toHeader(token);
    }

    private Map<String, Object> customClaimsMap(String username, String[] roles) {
        ImmutableMap.Builder<String, Object> builder = new ImmutableMap.Builder();
        // Handle username claim
        if (StringUtils.isNoneEmpty(username)) {
            if (usernameClaimName instanceof List && !((List<?>) usernameClaimName).isEmpty()) {
                // Handle nested username claim
                List<String> usernamePath = (List<String>) usernameClaimName;
                Map<String, Object> nestedUserMap = new HashMap<>();
                Map<String, Object> currentUserMap = nestedUserMap;

                // Build the nested structure for username
                for (int i = 0; i < usernamePath.size() - 1; i++) {
                    Map<String, Object> nextMap = new HashMap<>();
                    currentUserMap.put(usernamePath.get(i), nextMap);
                    currentUserMap = nextMap;
                }

                // Add the username at the deepest level
                currentUserMap.put(usernamePath.get(usernamePath.size() - 1), username);

                // Add the entire nested username structure to the builder
                builder.putAll(nestedUserMap);
            } else {
                // Simple case - no nesting for username
                builder.put(usernameClaimName.toString(), username);
            }
        }

        if (roles != null && roles.length > 0) {
            if (rolesClaimName.size() == 1) {
                // Simple case - no nesting
                builder.put(rolesClaimName.get(0), String.join(",", roles));
            } else {
                // Handle nested claims
                Map<String, Object> nestedMap = new HashMap<>();
                Map<String, Object> currentMap = nestedMap;

                // Build the nested structure
                for (int i = 0; i < rolesClaimName.size() - 1; i++) {
                    Map<String, Object> nextMap = new HashMap<>();
                    currentMap.put(rolesClaimName.get(i), nextMap);
                    currentMap = nextMap;
                }

                // Add the roles array at the deepest level
                currentMap.put(rolesClaimName.get(rolesClaimName.size() - 1), String.join(",", roles));

                // Add the entire nested structure to the builder
                builder.putAll(nestedMap);
            }
        }
        return builder.build();
    }

    Header generateValidTokenWithCustomClaims(String username, String[] roles, Map<String, Object> additionalClaims) {
        requireNonNull(username, "Username is required");
        requireNonNull(additionalClaims, "Custom claims are required");
        Map<String, Object> claims = new HashMap<>(customClaimsMap(username, roles));
        claims.putAll(additionalClaims);
        Date now = new Date();
        String token = Jwts.builder()
            .setClaims(claims)
            .setIssuer(ISSUER)
            .setSubject(subject(username))
            .setAudience(AUDIENCE)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(privateKey, RS256)
            .compact();
        return toHeader(token);
    }

    private BasicHeader toHeader(String token) {
        return new BasicHeader(headerName, token);
    }

    Header generateTokenWithoutPreferredUsername(String username) {
        requireNonNull(username, "Username is required");
        Date now = new Date();
        String token = Jwts.builder()
            .setIssuer(ISSUER)
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(privateKey, RS256)
            .compact();
        return toHeader(token);
    }

    public Header generateExpiredToken(String username) {
        requireNonNull(username, "Username is required");
        Date now = new Date(1000);
        String token = Jwts.builder()
            .setClaims(customClaimsMap(username, null))
            .setIssuer(ISSUER)
            .setSubject(subject(username))
            .setAudience(AUDIENCE)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(privateKey, RS256)
            .compact();
        return toHeader(token);
    }

    public Header generateTokenSignedWithKey(PrivateKey key, String username) {
        requireNonNull(key, "Private key is required");
        requireNonNull(username, "Username is required");
        Date now = new Date();
        String token = Jwts.builder()
            .setClaims(customClaimsMap(username, null))
            .setIssuer(ISSUER)
            .setSubject(subject(username))
            .setAudience(AUDIENCE)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + 3600 * 1000))
            .signWith(key, RS256)
            .compact();
        return toHeader(token);
    }

    private static String subject(String username) {
        return "subject-" + username;
    }
}
