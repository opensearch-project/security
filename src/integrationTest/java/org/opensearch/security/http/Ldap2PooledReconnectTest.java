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

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.RuleChain;

import org.opensearch.test.framework.AuthorizationBackend;
import org.opensearch.test.framework.AuthzDomain;
import org.opensearch.test.framework.LdapAuthorizationConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.ldap.EmbeddedLDAPServer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.opensearch.security.http.DirectoryInformationTrees.CN_GROUP_CREW;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_GROUPS_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_OPEN_SEARCH_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.LDIF_DATA;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_OPEN_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.USERNAME_ATTRIBUTE;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SPOCK;
import static org.opensearch.security.support.ConfigConstants.SECURITY_CACHE_TTL_MINUTES;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
* The ldap2 authorization backend keeps LDAPS connections in a pool that is filled when the security configuration
* is loaded. When the directory drops a pooled connection, ldaptive reopens it on the thread that runs the next
* search, which is a request thread that never created a connection itself. Role resolution must survive that.
*/
public class Ldap2PooledReconnectTest {

    private static final String POINTER_BACKEND_ROLES = "/backend_roles";

    private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

    // only authenticated internally (LDAP is used for roles), so not PASSWORD_SPOCK, which is too short for PBKDF2 in FIPS mode
    private static final User USER_SPOCK_INTERNAL = new User(USER_SPOCK).password("spock-internal-password");

    private static final EmbeddedLDAPServer embeddedLDAPServer = new EmbeddedLDAPServer(
        TEST_CERTIFICATES.getRootCertificateData(),
        TEST_CERTIFICATES.getLdapCertificateData(),
        LDIF_DATA
    );

    private static final LocalCluster cluster = new LocalCluster.Builder().testCertificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        // resolve roles against LDAP on every request instead of serving them from the user cache
        .nodeSettings(Map.of(SECURITY_CACHE_TTL_MINUTES, 0))
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_SPOCK_INTERNAL)
        .authz(new AuthzDomain("ldap2_roles").httpEnabled(true).authorizationBackend(new AuthorizationBackend("ldap2").config(() -> {
            Map<String, Object> config = new LdapAuthorizationConfigBuilder().hosts(
                List.of("localhost:" + embeddedLDAPServer.getLdapTlsPort())
            )
                .enableSsl(true)
                .bindDn(DN_OPEN_SEARCH_PEOPLE_TEST_ORG)
                .password(PASSWORD_OPEN_SEARCH)
                .userBase(DN_PEOPLE_TEST_ORG)
                .userSearch(USER_SEARCH)
                .usernameAttribute(USERNAME_ATTRIBUTE)
                .penTrustedCasFilePath(TEST_CERTIFICATES.getRootCertificate().getAbsolutePath())
                .roleBase(DN_GROUPS_TEST_ORG)
                .roleSearch("(uniqueMember={0})")
                .userRoleAttribute(null)
                .userRoleName("disabled")
                .roleName("cn")
                .resolveNestedRoles(true)
                .build();
            // a single pooled connection, so the request after the drop is guaranteed to get the dropped one
            config.put("pool.enabled", true);
            config.put("pool.min_size", 1);
            config.put("pool.max_size", 1);
            return config;
        })))
        .build();

    @ClassRule
    public static final RuleChain ruleChain = RuleChain.outerRule(embeddedLDAPServer).around(cluster);

    @Test
    public void shouldResolveBackendRolesAfterDirectoryDropsPooledConnection() {
        try (TestRestClient client = cluster.getRestClient(USER_SPOCK_INTERNAL)) {
            HttpResponse before = client.getAuthInfo();
            before.assertStatusCode(200);
            assertThat(before.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES), hasItem(CN_GROUP_CREW));

            embeddedLDAPServer.closeAllConnections();

            HttpResponse after = client.getAuthInfo();
            after.assertStatusCode(200);
            assertThat(after.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES), hasItem(CN_GROUP_CREW));
        }
    }
}
