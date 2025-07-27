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

import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.hc.core5.http.Header;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.JwtConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.log.LogsRule;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.opensearch.security.http.JwtAuthenticationTests.POINTER_BACKEND_ROLES;
import static org.opensearch.security.http.JwtAuthenticationTests.POINTER_USERNAME;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class JwtAuthenticationNestedClaimsTests {

    public static final List<String> USERNAME_CLAIM = List.of("preferred-username");
    public static final List<String> NESTED_ROLES = List.of("attributes", "roles");
    public static final List<String> NESTED_SUBJECT = List.of("attributes_sub", "sub");
    public static final List<String> NESTED_SUBJECT_ATTRIBUTES_ONLY = List.of("attributes", "sub");
    public static final List<String> ROLES_CLAIM = List.of("all_access", "securitymanager");

    public static final String USER_SUPERHERO = "superhero";
    private static final KeyPair KEY_PAIR1 = Keys.keyPairFor(SignatureAlgorithm.RS256);
    private static final String PUBLIC_KEY1 = new String(Base64.getEncoder().encode(KEY_PAIR1.getPublic().getEncoded()), US_ASCII);
    private static final String JWT_AUTH_HEADER = "jwt-auth";

    // Token factory for regular subject + nested roles 
    private static final JwtAuthorizationHeaderFactory tokenFactory1 = new JwtAuthorizationHeaderFactory(
        KEY_PAIR1.getPrivate(),
        USERNAME_CLAIM,
        NESTED_ROLES,
        JWT_AUTH_HEADER
    );
    
    // Token factory for nested subject + nested roles
    private static final JwtAuthorizationHeaderFactory tokenFactoryNestedSubjectAndRole = new JwtAuthorizationHeaderFactory(
        KEY_PAIR1.getPrivate(),
        NESTED_SUBJECT,
        NESTED_ROLES,
        JWT_AUTH_HEADER
    );
    
    // Token factory for both subject and roles nested under same "attributes" only
    private static final JwtAuthorizationHeaderFactory tokenFactoryAttributesOnly = new JwtAuthorizationHeaderFactory(
        KEY_PAIR1.getPrivate(),
        NESTED_SUBJECT_ATTRIBUTES_ONLY,
        NESTED_ROLES,
        JWT_AUTH_HEADER
    );

    // JWT domain for regular subject + nested roles 
    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN = new TestSecurityConfig.AuthcDomain(
        "jwt",
        BASIC_AUTH_DOMAIN_ORDER - 1
    ).jwtHttpAuthenticator(
        new JwtConfigBuilder().jwtHeader(JWT_AUTH_HEADER).signingKey(List.of(PUBLIC_KEY1)).subjectKey(USERNAME_CLAIM).rolesKey(NESTED_ROLES)
    ).backend("noop");
    
    // JWT domain for nested subject + nested roles
    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN_NESTED_SUBJECT = new TestSecurityConfig.AuthcDomain(
        "jwt-nested",
        BASIC_AUTH_DOMAIN_ORDER - 2
    ).jwtHttpAuthenticator(
        new JwtConfigBuilder().jwtHeader(JWT_AUTH_HEADER).signingKey(List.of(PUBLIC_KEY1)).subjectKey(NESTED_SUBJECT).rolesKey(NESTED_ROLES)
    ).backend("noop");
    
    // JWT domain for both subject and roles using "attributes" only
    public static final TestSecurityConfig.AuthcDomain JWT_AUTH_DOMAIN_ATTRIBUTES_ONLY = new TestSecurityConfig.AuthcDomain(
        "jwt-attributes-only",
        BASIC_AUTH_DOMAIN_ORDER - 3
    ).jwtHttpAuthenticator(
        new JwtConfigBuilder().jwtHeader(JWT_AUTH_HEADER).signingKey(List.of(PUBLIC_KEY1)).subjectKey(NESTED_SUBJECT_ATTRIBUTES_ONLY).rolesKey(NESTED_ROLES)
    ).backend("noop");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(JWT_AUTH_DOMAIN)
        .authc(JWT_AUTH_DOMAIN_NESTED_SUBJECT)
        .authc(JWT_AUTH_DOMAIN_ATTRIBUTES_ONLY)
        .build();

    @Rule
    public LogsRule logsRule = new LogsRule("org.opensearch.security.auth.http.jwt.HTTPJwtAuthenticator");

    // TODO write tests for scenarios where roles are in nested claim. i.e. rolesKey: ['attributes', 'roles']
    @Test
    public void shouldAuthenticateWithNestedRolesClaim() {
        // Create nested claims structure
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("roles", ROLES_CLAIM);

        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes", attributes);

        // Generate token with nested claims
        Header header = tokenFactory1.generateValidTokenWithCustomClaims(USER_SUPERHERO, null, nestedClaims);

        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(2));
            assertThat(roles, containsInAnyOrder("all_access", "securitymanager"));
        }
    }

    @Test
    public void shouldHandleMissingNestedRolesClaim() {
        // Create invalid nested claims structure
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("wrong", "missing"); // Invalid format - should be a list

        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes", attributes);

        Header header = tokenFactory1.generateValidTokenWithCustomClaims(USER_SUPERHERO, null, nestedClaims);

        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(0));
        }
    }
    
    @Test
    public void shouldAuthenticateWithNestedSubjectAndNestedRoles() {
        // Create nested subject structure - the key should match NESTED_SUBJECT path
        Map<String, Object> attributesSub = new HashMap<>();
        attributesSub.put("sub", USER_SUPERHERO);
        
        // Create nested roles structure
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("roles", ROLES_CLAIM);
        
        // Combine both in the claims
        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes_sub", attributesSub);
        nestedClaims.put("attributes", attributes);
        
        // Use the token factory with nested subject configuration
        Header header = tokenFactoryNestedSubjectAndRole.generateValidTokenWithCustomClaims(null, null, nestedClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(2));
            assertThat(roles, containsInAnyOrder("all_access", "securitymanager"));
        }
    }
    
    @Test
    public void shouldAuthenticateWithNestedSubjectAndSimpleRoles() {
        // Create nested subject structure
        Map<String, Object> attributesSub = new HashMap<>();
        attributesSub.put("sub", USER_SUPERHERO);
        
        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes_sub", attributesSub);
        
        Header header = tokenFactoryNestedSubjectAndRole.generateValidTokenWithCustomClaims(null, null, nestedClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            
            // Should have no roles since they're not in the expected nested location
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(0));
        }
    }
    
    // Negative test cases
    
    @Test
    public void shouldFailAuthenticationWithMissingNestedSubject() {
        // Create nested roles structure but missing nested subject
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("roles", ROLES_CLAIM);
        
        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes", attributes);
        // Missing attributes_sub structure
        
        Header header = tokenFactoryNestedSubjectAndRole.generateValidTokenWithCustomClaims(null, null, nestedClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            // Should fail authentication due to missing subject
            response.assertStatusCode(401);
        }
    }
    
    @Test
    public void shouldFailAuthenticationWithWrongNestedSubjectStructure() {
        // Create wrong nested subject structure
        Map<String, Object> attributesSub = new HashMap<>();
        attributesSub.put("wrong_key", USER_SUPERHERO);  // Wrong key, should be "sub"
        
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("roles", ROLES_CLAIM);
        
        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes_sub", attributesSub);
        nestedClaims.put("attributes", attributes);
        
        Header header = tokenFactoryNestedSubjectAndRole.generateValidTokenWithCustomClaims(null, null, nestedClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            // Should fail authentication due to wrong subject structure
            response.assertStatusCode(401);
        }
    }
    
    @Test
    public void shouldAuthenticateWithMissingRolesButValidSubject() {
        // Create nested subject structure but missing roles
        Map<String, Object> attributesSub = new HashMap<>();
        attributesSub.put("sub", USER_SUPERHERO);
        
        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes_sub", attributesSub);
        // Missing roles structure
        
        Header header = tokenFactoryNestedSubjectAndRole.generateValidTokenWithCustomClaims(null, null, nestedClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            // Should authenticate but with no roles
            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(0));
        }
    }
    
    @Test
    public void shouldHandleWrongNestedRolesStructure() {
        // Create nested subject structure with wrong roles structure
        Map<String, Object> attributesSub = new HashMap<>();
        attributesSub.put("sub", USER_SUPERHERO);
        
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("wrong_roles_key", ROLES_CLAIM);  // Wrong key, should be "roles"
        
        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes_sub", attributesSub);
        nestedClaims.put("attributes", attributes);
        
        Header header = tokenFactoryNestedSubjectAndRole.generateValidTokenWithCustomClaims(null, null, nestedClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            // Should authenticate but with no roles due to wrong roles structure
            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(0));
        }
    }
    
    @Test
    public void shouldFailAuthenticationWithCompletelyWrongTokenStructure() {
        // Create completely wrong token structure
        Map<String, Object> wrongClaims = new HashMap<>();
        wrongClaims.put("completely", "wrong");
        wrongClaims.put("structure", "invalid");
        
        Header header = tokenFactoryNestedSubjectAndRole.generateValidTokenWithCustomClaims(null, null, wrongClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            // Should fail authentication due to completely wrong structure
            response.assertStatusCode(401);
        }
    }
    
    @Test
    public void shouldAuthenticateWithBothSubjectAndRolesInAttributesOnly() {
        // Create nested structure where both subject and roles are under "attributes"
        // Subject path: attributes -> sub
        // Roles path: attributes -> roles
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", USER_SUPERHERO);
        attributes.put("roles", ROLES_CLAIM);
        
        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("attributes", attributes);
        
        // Use the token factory configured for attributes-only paths
        Header header = tokenFactoryAttributesOnly.generateValidTokenWithCustomClaims(null, null, nestedClaims);
        
        try (TestRestClient client = cluster.getRestClient(header)) {
            HttpResponse response = client.getAuthInfo();
            
            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SUPERHERO));
            
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(roles, hasSize(2));
            assertThat(roles, containsInAnyOrder("all_access", "securitymanager"));
        }
    }
    
}
