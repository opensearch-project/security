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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.runner.RunWith;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.AuthorizationBackend;
import org.opensearch.test.framework.AuthzDomain;
import org.opensearch.test.framework.LdapAuthenticationConfigBuilder;
import org.opensearch.test.framework.LdapAuthorizationConfigBuilder;
import org.opensearch.test.framework.RolesMapping;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AuthenticationBackend;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.HttpAuthenticator;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.ldap.EmbeddedLDAPServer;
import org.opensearch.test.framework.log.LogsRule;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.opensearch.security.http.DirectoryInformationTrees.CN_GROUP_ADMIN;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_GROUPS_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_OPEN_SEARCH_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.LDIF_DATA;
import static org.opensearch.security.http.DirectoryInformationTrees.LDIF_DATA_UPDATED_BACKEND_ROLES;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_KIRK;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_OPEN_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_SPOCK;
import static org.opensearch.security.http.DirectoryInformationTrees.USERNAME_ATTRIBUTE;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_KIRK;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SPOCK;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
* Test uses plain (non TLS) connection between OpenSearch and LDAP server.
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LdapAuthenticationCacheTest {

    private static final Logger log = LogManager.getLogger(LdapAuthenticationCacheTest.class);

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

    public static final EmbeddedLDAPServer embeddedLDAPServer = new EmbeddedLDAPServer(
        TEST_CERTIFICATES.getRootCertificateData(),
        TEST_CERTIFICATES.getLdapCertificateData(),
        LDIF_DATA
    );

    public static LocalCluster cluster = new LocalCluster.Builder().testCertificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of(
                ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS + "." + ADMIN_USER.getName(),
                List.of(USER_KIRK),
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_RESTAPI_ADMIN_ENABLED,
                true
            )
        )
        .authc(
            new AuthcDomain("ldap", BASIC_AUTH_DOMAIN_ORDER + 1, true).httpAuthenticator(new HttpAuthenticator("basic").challenge(false))
                .backend(
                    new AuthenticationBackend("ldap").config(
                        () -> LdapAuthenticationConfigBuilder.config()
                            // this port is available when embeddedLDAPServer is already started, therefore Supplier interface is used to
                            // postpone
                            // execution of the code in this block.
                            .enableSsl(false)
                            .enableStartTls(false)
                            .hosts(List.of("localhost:" + embeddedLDAPServer.getLdapNonTlsPort()))
                            .bindDn(DN_OPEN_SEARCH_PEOPLE_TEST_ORG)
                            .password(PASSWORD_OPEN_SEARCH)
                            .userBase(DN_PEOPLE_TEST_ORG)
                            .userSearch(USER_SEARCH)
                            .usernameAttribute(USERNAME_ATTRIBUTE)
                            .build()
                    )
                )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .rolesMapping(new RolesMapping(ALL_ACCESS).backendRoles(CN_GROUP_ADMIN))
        .authz(
            new AuthzDomain("ldap_roles").httpEnabled(true)
                .transportEnabled(true)
                .authorizationBackend(
                    new AuthorizationBackend("ldap").config(
                        () -> new LdapAuthorizationConfigBuilder().hosts(List.of("localhost:" + embeddedLDAPServer.getLdapNonTlsPort()))
                            .enableSsl(false)
                            .bindDn(DN_OPEN_SEARCH_PEOPLE_TEST_ORG)
                            .password(PASSWORD_OPEN_SEARCH)
                            .userBase(DN_PEOPLE_TEST_ORG)
                            .userSearch(USER_SEARCH)
                            .usernameAttribute(USERNAME_ATTRIBUTE)
                            .roleBase(DN_GROUPS_TEST_ORG)
                            .roleSearch("(uniqueMember={0})")
                            .userRoleAttribute(null)
                            .userRoleName("disabled")
                            .roleName("cn")
                            .resolveNestedRoles(true)
                            .build()
                    )
                )
        )
        .build();

    @ClassRule
    public static RuleChain ruleChain = RuleChain.outerRule(embeddedLDAPServer).around(cluster);

    @Rule
    public LogsRule logsRule = new LogsRule("com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend");

    @Test
    public void shouldAuthenticateUserWithLdap_positive() {
        try (TestRestClient client = cluster.getRestClient(USER_SPOCK, PASSWORD_SPOCK)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);

            assertThat(response.getTextArrayFromJsonBody("/backend_roles"), contains("crew"));
            assertThat(response.getTextArrayFromJsonBody("/backend_roles"), not(contains("enterprise")));
        }

        try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);

            assertThat(response.getTextArrayFromJsonBody("/backend_roles"), contains("admin"));
            assertThat(response.getTextArrayFromJsonBody("/backend_roles"), not(contains("enterprise")));
        }

        embeddedLDAPServer.loadLdifData(LDIF_DATA_UPDATED_BACKEND_ROLES);

        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.delete("_plugins/_security/api/cache/user/spock");

            response.assertStatusCode(200);
        }

        try (TestRestClient client = cluster.getRestClient(USER_SPOCK, PASSWORD_SPOCK)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);

            assertThat(response.getTextArrayFromJsonBody("/backend_roles"), contains("enterprise", "crew"));
        }

        try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {
            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);

            assertThat(response.getTextArrayFromJsonBody("/backend_roles"), contains("admin"));
            assertThat(response.getTextArrayFromJsonBody("/backend_roles"), not(contains("enterprise")));
        }
    }
}
