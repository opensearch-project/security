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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.LdapAuthenticationConfigBuilder;
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

import static org.opensearch.security.http.DirectoryInformationTrees.DN_CAPTAIN_SPOCK_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_OPEN_SEARCH_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.LDIF_DATA;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_OPEN_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_SPOCK;
import static org.opensearch.security.http.DirectoryInformationTrees.USERNAME_ATTRIBUTE;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SPOCK;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
* Test initiates plain (non-TLS) connection between OpenSearch and LDAP server and then in the course of the test connection is upgraded
* to TLS.
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LdapStartTlsAuthenticationTest {

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
        .authc(
            new AuthcDomain("ldap-config-id", BASIC_AUTH_DOMAIN_ORDER + 1, true).httpAuthenticator(
                new HttpAuthenticator("basic").challenge(false)
            )
                .backend(
                    new AuthenticationBackend("ldap").config(
                        () -> LdapAuthenticationConfigBuilder.config()
                            // this port is available when embeddedLDAPServer is already started, therefore Supplier interface is used
                            .hosts(List.of("localhost:" + embeddedLDAPServer.getLdapNonTlsPort()))
                            .enableSsl(false)
                            .enableStartTls(true)
                            .bindDn(DN_OPEN_SEARCH_PEOPLE_TEST_ORG)
                            .password(PASSWORD_OPEN_SEARCH)
                            .userBase(DN_PEOPLE_TEST_ORG)
                            .userSearch(USER_SEARCH)
                            .usernameAttribute(USERNAME_ATTRIBUTE)
                            .penTrustedCasFilePath(TEST_CERTIFICATES.getRootCertificate().getAbsolutePath())
                            .build()
                    )
                )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
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
        }
    }

    @Test
    public void shouldAuthenticateUserWithLdap_negativeWhenIncorrectPassword() {
        try (TestRestClient client = cluster.getRestClient(USER_SPOCK, "incorrect password")) {
            TestRestClient.HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            String expectedStackTraceFragment = "Unable to bind as user '".concat(DN_CAPTAIN_SPOCK_PEOPLE_TEST_ORG)
                .concat("' because the provided password was incorrect.");
            logsRule.assertThatStackTraceContain(expectedStackTraceFragment);
        }
    }
}
