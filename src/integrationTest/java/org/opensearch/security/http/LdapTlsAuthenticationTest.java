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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.message.BasicHeader;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.runner.RunWith;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.test.framework.AuthorizationBackend;
import org.opensearch.test.framework.AuthzDomain;
import org.opensearch.test.framework.LdapAuthenticationConfigBuilder;
import org.opensearch.test.framework.LdapAuthorizationConfigBuilder;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AuthenticationBackend;
import org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.HttpAuthenticator;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.ldap.EmbeddedLDAPServer;
import org.opensearch.test.framework.log.LogsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.security.Song.SONGS;
import static org.opensearch.security.http.DirectoryInformationTrees.CN_GROUP_ADMIN;
import static org.opensearch.security.http.DirectoryInformationTrees.CN_GROUP_BRIDGE;
import static org.opensearch.security.http.DirectoryInformationTrees.CN_GROUP_CREW;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_CAPTAIN_SPOCK_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_GROUPS_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_OPEN_SEARCH_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.DN_PEOPLE_TEST_ORG;
import static org.opensearch.security.http.DirectoryInformationTrees.LDIF_DATA;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_JEAN;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_KIRK;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_LEONARD;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_OPEN_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.PASSWORD_SPOCK;
import static org.opensearch.security.http.DirectoryInformationTrees.USERNAME_ATTRIBUTE;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_JEAN;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_KIRK;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_LEONARD;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SEARCH;
import static org.opensearch.security.http.DirectoryInformationTrees.USER_SPOCK;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.BASIC_AUTH_DOMAIN_ORDER;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.cluster.SearchRequestFactory.queryStringQueryRequest;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.isSuccessfulSearchResponse;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.numberOfTotalHitsIsEqualTo;
import static org.opensearch.test.framework.matcher.SearchResponseMatchers.searchHitsContainDocumentWithId;

/**
* Test uses plain TLS connection between OpenSearch and LDAP server.
*/
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class LdapTlsAuthenticationTest {

    private static final String SONG_INDEX_NAME = "song_lyrics";

    private static final String HEADER_NAME_IMPERSONATE = "opendistro_security_impersonate_as";

    private static final String PERSONAL_INDEX_NAME_SPOCK = "personal-" + USER_SPOCK;
    private static final String PERSONAL_INDEX_NAME_KIRK = "personal-" + USER_KIRK;

    private static final String POINTER_BACKEND_ROLES = "/backend_roles";
    private static final String POINTER_ROLES = "/roles";
    private static final String POINTER_USERNAME = "/user_name";
    private static final String POINTER_ERROR_REASON = "/error/reason";

    private static final String SONG_ID_1 = "l0001";
    private static final String SONG_ID_2 = "l0002";
    private static final String SONG_ID_3 = "l0003";

    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();

    private static final Role ROLE_INDEX_ADMINISTRATOR = new Role("index_administrator").indexPermissions("*").on("*");
    private static final Role ROLE_PERSONAL_INDEX_ACCESS = new Role("personal_index_access").indexPermissions("*")
        .on("personal-${attr.ldap.uid}");

    private static final EmbeddedLDAPServer embeddedLDAPServer = new EmbeddedLDAPServer(
        TEST_CERTIFICATES.getRootCertificateData(),
        TEST_CERTIFICATES.getLdapCertificateData(),
        LDIF_DATA
    );

    private static final Map<String, Object> USER_IMPERSONATION_CONFIGURATION = Map.of(
        "plugins.security.authcz.rest_impersonation_user." + USER_KIRK,
        List.of(USER_SPOCK)
    );

    private static final LocalCluster cluster = new LocalCluster.Builder().testCertificates(TEST_CERTIFICATES)
        .clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .nodeSettings(USER_IMPERSONATION_CONFIGURATION)
        .authc(
            new AuthcDomain("ldap", BASIC_AUTH_DOMAIN_ORDER + 1, true).httpAuthenticator(new HttpAuthenticator("basic").challenge(false))
                .backend(
                    new AuthenticationBackend("ldap").config(
                        () -> LdapAuthenticationConfigBuilder.config()
                            // this port is available when embeddedLDAPServer is already started, therefore Supplier interface is used
                            .hosts(List.of("localhost:" + embeddedLDAPServer.getLdapTlsPort()))
                            .enableSsl(true)
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
        .roles(ROLE_INDEX_ADMINISTRATOR, ROLE_PERSONAL_INDEX_ACCESS)
        .rolesMapping(
            new TestSecurityConfig.RoleMapping(ROLE_INDEX_ADMINISTRATOR.getName()).backendRoles(CN_GROUP_ADMIN),
            new TestSecurityConfig.RoleMapping(ROLE_PERSONAL_INDEX_ACCESS.getName()).backendRoles(CN_GROUP_CREW)
        )
        .authz(
            new AuthzDomain("ldap_roles").httpEnabled(true)
                .authorizationBackend(
                    new AuthorizationBackend("ldap").config(
                        () -> new LdapAuthorizationConfigBuilder().hosts(List.of("localhost:" + embeddedLDAPServer.getLdapTlsPort()))
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
                            .build()
                    )
                )
        )
        .build();

    @ClassRule
    public static final RuleChain ruleChain = RuleChain.outerRule(embeddedLDAPServer).around(cluster);

    @Rule
    public LogsRule logsRule = new LogsRule("com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend");

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(SONG_INDEX_NAME).setId(SONG_ID_1).setRefreshPolicy(IMMEDIATE).setSource(SONGS[0].asMap()).get();
            client.prepareIndex(PERSONAL_INDEX_NAME_SPOCK).setId(SONG_ID_2).setRefreshPolicy(IMMEDIATE).setSource(SONGS[1].asMap()).get();
            client.prepareIndex(PERSONAL_INDEX_NAME_KIRK).setId(SONG_ID_3).setRefreshPolicy(IMMEDIATE).setSource(SONGS[2].asMap()).get();
        }
    }

    @Test
    public void shouldAuthenticateUserWithLdap_positiveSpockUser() {
        try (TestRestClient client = cluster.getRestClient(USER_SPOCK, PASSWORD_SPOCK)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_SPOCK));
        }
    }

    @Test
    public void shouldAuthenticateUserWithLdap_positiveKirkUser() {
        try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            String username = response.getTextFromJsonBody(POINTER_USERNAME);
            assertThat(username, equalTo(USER_KIRK));
        }
    }

    @Test
    public void shouldAuthenticateUserWithLdap_negativeWhenIncorrectPassword() {
        try (TestRestClient client = cluster.getRestClient(USER_SPOCK, "incorrect password")) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            String expectedStackTraceFragment = "Unable to bind as user '".concat(DN_CAPTAIN_SPOCK_PEOPLE_TEST_ORG)
                .concat("' because the provided password was incorrect.");
            logsRule.assertThatStackTraceContain(expectedStackTraceFragment);
        }
    }

    @Test
    public void shouldAuthenticateUserWithLdap_negativeWhenIncorrectUsername() {
        final String username = "invalid-user-name";
        try (TestRestClient client = cluster.getRestClient(username, PASSWORD_SPOCK)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            logsRule.assertThatStackTraceContain(String.format("No user %s found", username));
        }
    }

    @Test
    public void shouldAuthenticateUserWithLdap_negativeWhenUserDoesNotExist() {
        final String username = "doesNotExist";
        try (TestRestClient client = cluster.getRestClient(username, "password")) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            logsRule.assertThatStackTraceContain(String.format("No user %s found", username));
        }
    }

    @Test
    public void shouldResolveUserRolesAgainstLdapBackend_positiveSpockUser() {
        try (TestRestClient client = cluster.getRestClient(USER_SPOCK, PASSWORD_SPOCK)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, contains(CN_GROUP_CREW));
            assertThat(response.getTextArrayFromJsonBody(POINTER_ROLES), contains(ROLE_PERSONAL_INDEX_ACCESS.getName()));
        }
    }

    @Test
    public void shouldResolveUserRolesAgainstLdapBackend_positiveKirkUser() {
        try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            assertThat(response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES), contains(CN_GROUP_ADMIN));
            assertThat(response.getTextArrayFromJsonBody(POINTER_ROLES), contains(ROLE_INDEX_ADMINISTRATOR.getName()));
        }
    }

    @Test
    public void shouldPerformAuthorizationAgainstLdapToAccessIndex_positive() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(USER_KIRK, PASSWORD_KIRK)) {
            SearchRequest request = queryStringQueryRequest(SONG_INDEX_NAME, "*");

            SearchResponse searchResponse = client.search(request, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, SONG_INDEX_NAME, SONG_ID_1));
        }
    }

    @Test
    public void shouldPerformAuthorizationAgainstLdapToAccessIndex_negative() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(USER_LEONARD, PASSWORD_LEONARD)) {
            SearchRequest request = queryStringQueryRequest(SONG_INDEX_NAME, "*");

            assertThatThrownBy(() -> client.search(request, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldResolveUserAttributesLoadedFromLdap_positive() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(USER_SPOCK, PASSWORD_SPOCK)) {
            SearchRequest request = queryStringQueryRequest(PERSONAL_INDEX_NAME_SPOCK, "*");

            SearchResponse searchResponse = client.search(request, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, PERSONAL_INDEX_NAME_SPOCK, SONG_ID_2));
        }
    }

    @Test
    public void shouldResolveUserAttributesLoadedFromLdap_negative() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(USER_SPOCK, PASSWORD_SPOCK)) {
            SearchRequest request = queryStringQueryRequest(PERSONAL_INDEX_NAME_KIRK, "*");

            assertThatThrownBy(() -> client.search(request, DEFAULT), statusException(FORBIDDEN));
        }
    }

    @Test
    public void shouldResolveNestedGroups_positive() {
        try (TestRestClient client = cluster.getRestClient(USER_JEAN, PASSWORD_JEAN)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(2));
            // CN_GROUP_CREW is retrieved recursively: cn=Jean,ou=people,o=test.org -> cn=bridge,ou=groups,o=test.org ->
            // cn=crew,ou=groups,o=test.org
            assertThat(backendRoles, containsInAnyOrder(CN_GROUP_CREW, CN_GROUP_BRIDGE));
            assertThat(response.getTextArrayFromJsonBody(POINTER_ROLES), contains(ROLE_PERSONAL_INDEX_ACCESS.getName()));
        }
    }

    @Test
    public void shouldResolveNestedGroups_negative() {
        try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {
            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(200);
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, not(containsInAnyOrder(CN_GROUP_CREW)));
        }
    }

    @Test
    public void shouldImpersonateUser_positive() {
        try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {

            HttpResponse response = client.getAuthInfo(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_SPOCK));

            response.assertStatusCode(200);
            assertThat(response.getTextFromJsonBody(POINTER_USERNAME), equalTo(USER_SPOCK));
            List<String> backendRoles = response.getTextArrayFromJsonBody(POINTER_BACKEND_ROLES);
            assertThat(backendRoles, hasSize(1));
            assertThat(backendRoles, contains(CN_GROUP_CREW));
        }
    }

    @Test
    public void shouldImpersonateUser_negativeJean() {
        try (TestRestClient client = cluster.getRestClient(USER_KIRK, PASSWORD_KIRK)) {

            HttpResponse response = client.getAuthInfo(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_JEAN));

            response.assertStatusCode(403);
            String expectedMessage = String.format("'%s' is not allowed to impersonate as '%s'", USER_KIRK, USER_JEAN);
            assertThat(response.getTextFromJsonBody(POINTER_ERROR_REASON), equalTo(expectedMessage));
        }
    }

    @Test
    public void shouldImpersonateUser_negativeKirk() {
        try (TestRestClient client = cluster.getRestClient(USER_JEAN, PASSWORD_JEAN)) {

            HttpResponse response = client.getAuthInfo(new BasicHeader(HEADER_NAME_IMPERSONATE, USER_KIRK));

            response.assertStatusCode(403);
            String expectedMessage = String.format("'%s' is not allowed to impersonate as '%s'", USER_JEAN, USER_KIRK);
            assertThat(response.getTextFromJsonBody(POINTER_ERROR_REASON), equalTo(expectedMessage));
        }
    }

    @Test
    public void shouldAccessImpersonatedUserPersonalIndex_positive() throws IOException {
        BasicHeader impersonateHeader = new BasicHeader(HEADER_NAME_IMPERSONATE, USER_SPOCK);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(USER_KIRK, PASSWORD_KIRK, impersonateHeader)) {
            SearchRequest request = queryStringQueryRequest(PERSONAL_INDEX_NAME_SPOCK, "*");

            SearchResponse searchResponse = client.search(request, DEFAULT);

            assertThat(searchResponse, isSuccessfulSearchResponse());
            assertThat(searchResponse, numberOfTotalHitsIsEqualTo(1));
            assertThat(searchResponse, searchHitsContainDocumentWithId(0, PERSONAL_INDEX_NAME_SPOCK, SONG_ID_2));
        }
    }

    @Test
    public void shouldAccessImpersonatedUserPersonalIndex_negative() throws IOException {
        BasicHeader impersonateHeader = new BasicHeader(HEADER_NAME_IMPERSONATE, USER_SPOCK);
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(USER_KIRK, PASSWORD_KIRK, impersonateHeader)) {
            SearchRequest request = queryStringQueryRequest(PERSONAL_INDEX_NAME_KIRK, "*");

            assertThatThrownBy(() -> client.search(request, DEFAULT), statusException(FORBIDDEN));
        }
    }
}
