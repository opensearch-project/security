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

package org.opensearch.security.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.StringJoiner;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableMap;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.awaitility.Awaitility;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;

import org.opensearch.common.CheckedConsumer;
import org.opensearch.common.CheckedSupplier;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.ConfigurationFiles;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.hasher.BCryptPasswordHasher;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.CrossClusterSearchTests.PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.ENDPOINTS_WITH_PERMISSIONS;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.RELOAD_CERTS_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE;
import static org.opensearch.test.framework.TestSecurityConfig.REST_ADMIN_REST_API_ACCESS;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
public abstract class AbstractApiIntegrationTest extends RandomizedTest {

    private static final Logger LOGGER = LogManager.getLogger(TestSecurityConfig.class);

    public static final String NEW_USER = "new-user";

    public static final String REST_ADMIN_USER = "rest-api-admin";

    public static final String ADMIN_USER_NAME = "admin";

    public static final String DEFAULT_PASSWORD = "secret";

    public static final ToXContentObject EMPTY_BODY = (builder, params) -> builder.startObject().endObject();

    public static Path configurationFolder;

    public static ImmutableMap.Builder<String, Object> clusterSettings = ImmutableMap.builder();

    protected static TestSecurityConfig testSecurityConfig = new TestSecurityConfig();

    public static LocalCluster localCluster;

    public static PasswordHasher passwordHasher = new BCryptPasswordHasher();

    @BeforeClass
    public static void startCluster() throws IOException {
        configurationFolder = ConfigurationFiles.createConfigurationDirectory();
        extendConfiguration();
        clusterSettings.put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
            .put(PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_admin__all_access", REST_ADMIN_REST_API_ACCESS))
            .put(SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE, randomBoolean());
        final var clusterManager = randomFrom(List.of(ClusterManager.THREE_CLUSTER_MANAGERS, ClusterManager.SINGLENODE));
        final var localClusterBuilder = new LocalCluster.Builder().clusterManager(clusterManager)
            .nodeSettings(clusterSettings.buildKeepingLast())
            .defaultConfigurationInitDirectory(configurationFolder.toString())
            .loadConfigurationIntoIndex(false);
        localCluster = localClusterBuilder.build();
        localCluster.before();
        try (TestRestClient client = localCluster.getRestClient(ADMIN_USER_NAME, DEFAULT_PASSWORD)) {
            Awaitility.await()
                .alias("Load default configuration")
                .until(() -> client.securityHealth().getTextFromJsonBody("/status"), equalTo("UP"));
        }
    }

    private static void extendConfiguration() throws IOException {
        extendActionGroups(configurationFolder, testSecurityConfig.actionGroups());
        extendRoles(configurationFolder, testSecurityConfig.roles());
        extendRolesMapping(configurationFolder, testSecurityConfig.rolesMapping());
        extendUsers(configurationFolder, testSecurityConfig.getUsers());
    }

    private static void extendUsers(final Path configFolder, final List<TestSecurityConfig.User> users) throws IOException {
        if (users == null) return;
        if (users.isEmpty()) return;
        LOGGER.info("Adding users to the default configuration: ");
        try (final var contentBuilder = XContentFactory.yamlBuilder()) {
            contentBuilder.startObject();
            for (final var u : users) {
                LOGGER.info("\t\t - {}", u.getName());
                contentBuilder.field(u.getName());
                u.toXContent(contentBuilder, ToXContent.EMPTY_PARAMS);
            }
            contentBuilder.endObject();
            ConfigurationFiles.writeToConfig(CType.INTERNALUSERS, configFolder, removeDashes(contentBuilder.toString()));
        }
    }

    private static void extendActionGroups(final Path configFolder, final List<TestSecurityConfig.ActionGroup> actionGroups)
        throws IOException {
        if (actionGroups == null) return;
        if (actionGroups.isEmpty()) return;
        LOGGER.info("Adding action groups to the default configuration: ");
        try (final var contentBuilder = XContentFactory.yamlBuilder()) {
            contentBuilder.startObject();
            for (final var ag : actionGroups) {
                LOGGER.info("\t\t - {}", ag.name());
                contentBuilder.field(ag.name());
                ag.toXContent(contentBuilder, ToXContent.EMPTY_PARAMS);
            }
            contentBuilder.endObject();
            ConfigurationFiles.writeToConfig(CType.ACTIONGROUPS, configFolder, removeDashes(contentBuilder.toString()));
        }
    }

    private static void extendRoles(final Path configFolder, final List<TestSecurityConfig.Role> roles) throws IOException {
        if (roles == null) return;
        if (roles.isEmpty()) return;
        LOGGER.info("Adding roles to the default configuration: ");
        try (final var contentBuilder = XContentFactory.yamlBuilder()) {
            contentBuilder.startObject();
            for (final var r : roles) {
                LOGGER.info("\t\t - {}", r.getName());
                contentBuilder.field(r.getName());
                r.toXContent(contentBuilder, ToXContent.EMPTY_PARAMS);
            }
            contentBuilder.endObject();
            ConfigurationFiles.writeToConfig(CType.ROLES, configFolder, removeDashes(contentBuilder.toString()));
        }
    }

    private static void extendRolesMapping(final Path configFolder, final List<TestSecurityConfig.RoleMapping> rolesMapping)
        throws IOException {
        if (rolesMapping == null) return;
        if (rolesMapping.isEmpty()) return;
        LOGGER.info("Adding roles mapping to the default configuration: ");
        try (final var contentBuilder = XContentFactory.yamlBuilder()) {
            contentBuilder.startObject();
            for (final var rm : rolesMapping) {
                LOGGER.info("\t\t - {}", rm.name());
                contentBuilder.field(rm.name());
                rm.toXContent(contentBuilder, ToXContent.EMPTY_PARAMS);
            }
            contentBuilder.endObject();
            ConfigurationFiles.writeToConfig(CType.ROLESMAPPING, configFolder, removeDashes(contentBuilder.toString()));
        }
    }

    private static String removeDashes(final String content) {
        return content.replace("---", "");
    }

    protected static String[] allRestAdminPermissions() {
        final var permissions = new String[ENDPOINTS_WITH_PERMISSIONS.size() + 1]; // 1 additional action for SSL update certs
        var counter = 0;
        for (final var e : ENDPOINTS_WITH_PERMISSIONS.entrySet()) {
            if (e.getKey() == Endpoint.SSL) {
                permissions[counter] = e.getValue().build(CERTS_INFO_ACTION);
                permissions[++counter] = e.getValue().build(RELOAD_CERTS_ACTION);
            } else if (e.getKey() == Endpoint.CONFIG) {
                permissions[counter++] = e.getValue().build(SECURITY_CONFIG_UPDATE);
            } else {
                permissions[counter++] = e.getValue().build();
            }
        }
        return permissions;
    }

    protected static String restAdminPermission(Endpoint endpoint) {
        return restAdminPermission(endpoint, null);
    }

    protected static String restAdminPermission(Endpoint endpoint, String action) {
        if (action != null) {
            return ENDPOINTS_WITH_PERMISSIONS.get(endpoint).build(action);
        } else {
            return ENDPOINTS_WITH_PERMISSIONS.get(endpoint).build();
        }
    }

    protected String randomRestAdminPermission() {
        final var permissions = List.of(allRestAdminPermissions());
        return randomFrom(permissions);
    }

    @AfterClass
    public static void stopCluster() throws IOException {
        if (localCluster != null) localCluster.close();
        FileUtils.deleteDirectory(configurationFolder.toFile());
    }

    protected void withUser(final String user, final CheckedConsumer<TestRestClient, Exception> restClientHandler) throws Exception {
        withUser(user, DEFAULT_PASSWORD, restClientHandler);
    }

    protected void withUser(final String user, final String password, final CheckedConsumer<TestRestClient, Exception> restClientHandler)
        throws Exception {
        try (TestRestClient client = localCluster.getRestClient(user, password)) {
            restClientHandler.accept(client);
        }
    }

    protected void withUser(
        final String user,
        final CertificateData certificateData,
        final CheckedConsumer<TestRestClient, Exception> restClientHandler
    ) throws Exception {
        withUser(user, DEFAULT_PASSWORD, certificateData, restClientHandler);
    }

    protected void withUser(
        final String user,
        final String password,
        final CertificateData certificateData,
        final CheckedConsumer<TestRestClient, Exception> restClientHandler
    ) throws Exception {
        try (final TestRestClient client = localCluster.getRestClient(user, password, certificateData)) {
            restClientHandler.accept(client);
        }
    }

    protected String apiPathPrefix() {
        return randomFrom(List.of(LEGACY_OPENDISTRO_PREFIX, PLUGINS_PREFIX));
    }

    protected String securityPath(String... path) {
        final var fullPath = new StringJoiner("/");
        fullPath.add(apiPathPrefix());
        if (path != null) {
            for (final var p : path)
                fullPath.add(p);
        }
        return fullPath.toString();
    }

    protected String api() {
        return String.format("%s/api", securityPath());
    }

    protected String apiPath(final String... path) {

        final var fullPath = new StringJoiner("/");
        fullPath.add(api());

        for (final var p : path) {
            fullPath.add(p);
        }
        return fullPath.toString();
    }

    void badRequestWithMessage(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback, final String expectedMessage)
        throws Exception {
        final var response = badRequest(endpointCallback);
        assertThat(response.getBody(), response.getTextFromJsonBody("/message"), is(expectedMessage));
    }

    TestRestClient.HttpResponse badRequest(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
        assertResponseBody(response.getBody());
        return response;
    }

    TestRestClient.HttpResponse created(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback) throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_CREATED));
        assertResponseBody(response.getBody());
        assertThat(response.getBody(), response.getTextFromJsonBody("/status"), equalToIgnoringCase("created"));
        return response;
    }

    void forbidden(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback, final String expectedMessage)
        throws Exception {
        final var response = forbidden(endpointCallback);
        assertThat(response.getBody(), response.getTextFromJsonBody("/message"), is(expectedMessage));
    }

    TestRestClient.HttpResponse forbidden(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback) throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        assertResponseBody(response.getBody());
        return response;
    }

    TestRestClient.HttpResponse methodNotAllowed(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_METHOD_NOT_ALLOWED));
        assertResponseBody(response.getBody());
        return response;
    }

    TestRestClient.HttpResponse notImplemented(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), is(HttpStatus.SC_NOT_IMPLEMENTED));
        assertResponseBody(response.getBody());
        return response;
    }

    TestRestClient.HttpResponse notFound(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback) throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_NOT_FOUND));
        assertResponseBody(response.getBody());
        return response;
    }

    void notFound(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback, final String expectedMessage)
        throws Exception {
        final var response = notFound(endpointCallback);
        assertThat(response.getBody(), response.getTextFromJsonBody("/message"), is(expectedMessage));
    }

    TestRestClient.HttpResponse ok(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback) throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertResponseBody(response.getBody());
        return response;
    }

    TestRestClient.HttpResponse unauthorized(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_UNAUTHORIZED));
        assertResponseBody(response.getBody());
        return response;
    }

    void assertResponseBody(final String responseBody) {
        assertThat(responseBody, notNullValue());
        assertThat(responseBody, not(equalTo("")));
    }

}
