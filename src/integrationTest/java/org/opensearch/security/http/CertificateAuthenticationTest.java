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

import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.HttpAuthenticator;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class CertificateAuthenticationTest {

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    public static final String POINTER_BACKEND_ROLES = "/backend_roles";
    public static final String POINTER_ROLES = "/roles";

    private static final String USER_SPOCK = "spock";
    private static final String USER_KIRK = "kirk";

    private static final String BACKEND_ROLE_BRIDGE = "bridge";
    private static final String BACKEND_ROLE_CAPTAIN = "captain";

    private static final Role ROLE_ALL_INDEX_SEARCH = new Role("all-index-search").indexPermissions("indices:data/read/search").on("*");

    private static final Map<String, Object> CERT_AUTH_CONFIG = Map.of("username_attribute", "cn", "roles_attribute", "ou");

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().nodeSettings(
        Map.of("plugins.security.ssl.http.clientauth_mode", "OPTIONAL")
    )
        .clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .authc(
            new AuthcDomain("clientcert_auth_domain", -1, true).httpAuthenticator(
                new HttpAuthenticator("clientcert").challenge(false).config(CERT_AUTH_CONFIG)
            ).backend("noop")
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .roles(ROLE_ALL_INDEX_SEARCH)
        .users(USER_ADMIN)
        .rolesMapping(new TestSecurityConfig.RoleMapping(ROLE_ALL_INDEX_SEARCH.getName()).backendRoles(BACKEND_ROLE_BRIDGE))
        .build();

    private static final TestCertificates TEST_CERTIFICATES = cluster.getTestCertificates();

    @Test
    public void shouldAuthenticateUserWithBasicAuthWhenCertificateAuthenticationIsConfigured() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_OK);
        }
    }

    @Test
    public void shouldAuthenticateUserWithCertificate_positiveUserSpoke() {
        CertificateData userSpockCertificate = TEST_CERTIFICATES.issueUserCertificate(BACKEND_ROLE_BRIDGE, USER_SPOCK);
        try (TestRestClient client = cluster.getRestClient(userSpockCertificate)) {

            client.confirmCorrectCredentials(USER_SPOCK);
        }
    }

    @Test
    public void shouldAuthenticateUserWithCertificate_positiveUserKirk() {
        CertificateData userSpockCertificate = TEST_CERTIFICATES.issueUserCertificate(BACKEND_ROLE_BRIDGE, USER_KIRK);
        try (TestRestClient client = cluster.getRestClient(userSpockCertificate)) {

            client.confirmCorrectCredentials(USER_KIRK);
        }
    }

    @Test
    public void shouldAuthenticateUserWithCertificate_negative() {
        CertificateData untrustedUserCertificate = TEST_CERTIFICATES.createSelfSignedCertificate("CN=untrusted");
        try (TestRestClient client = cluster.getRestClient(untrustedUserCertificate)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
        }
    }

    @Test
    public void shouldRetrieveBackendRoleFromCertificate_positiveRoleBridge() {
        CertificateData userSpockCertificate = TEST_CERTIFICATES.issueUserCertificate(BACKEND_ROLE_BRIDGE, USER_KIRK);
        try (TestRestClient client = cluster.getRestClient(userSpockCertificate)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(1));
            assertThat(backendRoles, containsInAnyOrder(BACKEND_ROLE_BRIDGE));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
            assertThat(roles, hasSize(1));
            assertThat(roles, containsInAnyOrder(ROLE_ALL_INDEX_SEARCH.getName()));
        }
    }

    @Test
    public void shouldRetrieveBackendRoleFromCertificate_positiveRoleCaptain() {
        CertificateData userSpockCertificate = TEST_CERTIFICATES.issueUserCertificate(BACKEND_ROLE_CAPTAIN, USER_KIRK);
        try (TestRestClient client = cluster.getRestClient(userSpockCertificate)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(1));
            assertThat(backendRoles, containsInAnyOrder(BACKEND_ROLE_CAPTAIN));
            List<String> roles = response.getTextArrayFromJsonBody(POINTER_ROLES);
            assertThat(roles, hasSize(0));
        }
    }
}
