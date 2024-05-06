/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.client.Client;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.framework.AsyncActions;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityConfigurationTests {

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);
    private static final User LIMITED_USER = new User("limited-user").roles(
        new Role("limited-role").indexPermissions("indices:data/read/search", "indices:data/read/get").on("user-${user.name}")
    );
    public static final String LIMITED_USER_INDEX = "user-" + LIMITED_USER.getName();
    public static final String ADDITIONAL_USER_1 = "additional00001";
    public static final String ADDITIONAL_PASSWORD_1 = "user 1 fair password";

    public static final String ADDITIONAL_USER_2 = "additional2";
    public static final String ADDITIONAL_PASSWORD_2 = "user 2 fair password";
    public static final String CREATE_USER_BODY = "{\"password\": \"%s\",\"opendistro_security_roles\": []}";
    public static final String INTERNAL_USERS_RESOURCE = "_plugins/_security/api/internalusers/";
    public static final String ID_1 = "one";
    public static final String PROHIBITED_INDEX = "prohibited";
    public static final String ID_2 = "two";

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN, LIMITED_USER)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST,
                false
            )
        )
        .build();

    @Rule
    public TemporaryFolder configurationDirectory = new TemporaryFolder();

    @BeforeClass
    public static void initData() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(LIMITED_USER_INDEX).setId(ID_1).setRefreshPolicy(IMMEDIATE).setSource("foo", "bar").get();
            client.prepareIndex(PROHIBITED_INDEX).setId(ID_2).setRefreshPolicy(IMMEDIATE).setSource("three", "four").get();
        }
    }

    @Test
    public void shouldCreateUserViaRestApi_success() {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse httpResponse = client.putJson(
                INTERNAL_USERS_RESOURCE + ADDITIONAL_USER_1,
                String.format(CREATE_USER_BODY, ADDITIONAL_PASSWORD_1)
            );

            assertThat(httpResponse.getStatusCode(), equalTo(201));
        }
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.confirmCorrectCredentials(USER_ADMIN.getName());
        }
        try (TestRestClient client = cluster.getRestClient(ADDITIONAL_USER_1, ADDITIONAL_PASSWORD_1)) {
            client.confirmCorrectCredentials(ADDITIONAL_USER_1);
        }
    }

    @Test
    public void shouldCreateUserViaRestApi_failure() {
        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            HttpResponse httpResponse = client.putJson(
                INTERNAL_USERS_RESOURCE + ADDITIONAL_USER_1,
                String.format(CREATE_USER_BODY, ADDITIONAL_PASSWORD_1)
            );

            httpResponse.assertStatusCode(403);
        }
    }

    @Test
    public void shouldAuthenticateAsAdminWithCertificate_positive() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {
            HttpResponse httpResponse = client.get("_plugins/_security/whoami");

            httpResponse.assertStatusCode(200);
            assertThat(httpResponse.getTextFromJsonBody("/is_admin"), equalTo("true"));
        }
    }

    @Test
    public void shouldAuthenticateAsAdminWithCertificate_negativeSelfSignedCertificate() {
        TestCertificates testCertificates = cluster.getTestCertificates();
        try (TestRestClient client = cluster.getRestClient(testCertificates.createSelfSignedCertificate("CN=bond"))) {
            HttpResponse httpResponse = client.get("_plugins/_security/whoami");

            httpResponse.assertStatusCode(200);
            assertThat(httpResponse.getTextFromJsonBody("/is_admin"), equalTo("false"));
        }
    }

    @Test
    public void shouldAuthenticateAsAdminWithCertificate_negativeIncorrectDn() {
        TestCertificates testCertificates = cluster.getTestCertificates();
        try (TestRestClient client = cluster.getRestClient(testCertificates.createAdminCertificate("CN=non_admin"))) {
            HttpResponse httpResponse = client.get("_plugins/_security/whoami");

            httpResponse.assertStatusCode(200);
            assertThat(httpResponse.getTextFromJsonBody("/is_admin"), equalTo("false"));
        }
    }

    @Test
    public void shouldCreateUserViaRestApiWhenAdminIsAuthenticatedViaCertificate_positive() {
        try (TestRestClient client = cluster.getRestClient(cluster.getAdminCertificate())) {

            HttpResponse httpResponse = client.putJson(
                INTERNAL_USERS_RESOURCE + ADDITIONAL_USER_2,
                String.format(CREATE_USER_BODY, ADDITIONAL_PASSWORD_2)
            );

            httpResponse.assertStatusCode(201);
        }
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.confirmCorrectCredentials(USER_ADMIN.getName());
        }
        try (TestRestClient client = cluster.getRestClient(ADDITIONAL_USER_2, ADDITIONAL_PASSWORD_2)) {
            client.confirmCorrectCredentials(ADDITIONAL_USER_2);
        }
    }

    @Test
    public void shouldCreateUserViaRestApiWhenAdminIsAuthenticatedViaCertificate_negative() {
        TestCertificates testCertificates = cluster.getTestCertificates();
        try (TestRestClient client = cluster.getRestClient(testCertificates.createSelfSignedCertificate("CN=attacker"))) {
            HttpResponse httpResponse = client.putJson(
                INTERNAL_USERS_RESOURCE + ADDITIONAL_USER_2,
                String.format(CREATE_USER_BODY, ADDITIONAL_PASSWORD_2)
            );

            httpResponse.assertStatusCode(401);
        }
    }

    @Test
    public void shouldStillWorkAfterUpdateOfSecurityConfig() {
        List<User> users = new ArrayList<>(cluster.getConfiguredUsers());
        User newUser = new User("new-user");
        users.add(newUser);

        cluster.updateUserConfiguration(users);

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.confirmCorrectCredentials(USER_ADMIN.getName());
        }
        try (TestRestClient client = cluster.getRestClient(newUser)) {
            client.confirmCorrectCredentials(newUser.getName());
        }
    }

    @Test
    public void shouldAccessIndexWithPlaceholder_positive() {
        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            HttpResponse httpResponse = client.get(LIMITED_USER_INDEX + "/_doc/" + ID_1);

            httpResponse.assertStatusCode(200);
        }
    }

    @Test
    public void shouldAccessIndexWithPlaceholder_negative() {
        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            HttpResponse httpResponse = client.get(PROHIBITED_INDEX + "/_doc/" + ID_2);

            httpResponse.assertStatusCode(403);
        }
    }

    @Test
    public void shouldUseSecurityAdminTool() throws Exception {
        SecurityAdminLauncher securityAdminLauncher = new SecurityAdminLauncher(cluster.getHttpPort(), cluster.getTestCertificates());
        File rolesMapping = configurationDirectory.newFile(CType.ROLESMAPPING.configFileName());
        ConfigurationFiles.copyResourceToFile(CType.ROLESMAPPING.configFileName(), rolesMapping.toPath());

        int exitCode = securityAdminLauncher.updateRoleMappings(rolesMapping);

        assertThat(exitCode, equalTo(0));
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            Awaitility.await()
                .alias("Waiting for rolemapping 'readall' availability.")
                .until(() -> client.get("_plugins/_security/api/rolesmapping/readall").getStatusCode(), equalTo(200));
        }
    }

    @Test
    public void testParallelTenantPutRequests() throws Exception {
        final String TENANT_ENDPOINT = "_plugins/_security/api/tenants/tenant1";
        final String TENANT_BODY = "{\"description\":\"create new tenant\"}";
        final String TENANT_BODY_TWO = "{\"description\":\"update tenant\"}";

        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {

            final CountDownLatch countDownLatch = new CountDownLatch(1);
            final List<CompletableFuture<TestRestClient.HttpResponse>> conflictingRequests = AsyncActions.generate(() -> {
                countDownLatch.await();
                return client.putJson(TENANT_ENDPOINT, TENANT_BODY);
            }, 4, 4);

            // Make sure all requests start at the same time
            countDownLatch.countDown();

            AtomicInteger numCreatedResponses = new AtomicInteger();
            AsyncActions.getAll(conflictingRequests, 1, TimeUnit.SECONDS).forEach((response) -> {
                assertThat(response.getStatusCode(), anyOf(equalTo(HttpStatus.SC_CREATED), equalTo(HttpStatus.SC_CONFLICT)));
                if (response.getStatusCode() == HttpStatus.SC_CREATED) numCreatedResponses.getAndIncrement();
            });
            assertThat(numCreatedResponses.get(), equalTo(1)); // should only be one 201

            TestRestClient.HttpResponse getResponse = client.get(TENANT_ENDPOINT); // make sure the one 201 works
            assertThat(getResponse.getBody(), containsString("create new tenant"));

            TestRestClient.HttpResponse updateResponse = client.putJson(TENANT_ENDPOINT, TENANT_BODY_TWO);
            assertThat(updateResponse.getStatusCode(), equalTo(HttpStatus.SC_OK));

            getResponse = client.get(TENANT_ENDPOINT); // make sure update works
            assertThat(getResponse.getBody(), containsString("update tenant"));
        }
    }
}
