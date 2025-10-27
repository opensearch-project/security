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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

import com.carrotsearch.randomizedtesting.RandomizedTest;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.runner.RunWith;

import org.opensearch.common.CheckedSupplier;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.security.dlic.rest.api.Endpoint;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.CrossClusterSearchTests.PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;
import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGINS_PREFIX;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.ENDPOINTS_WITH_PERMISSIONS;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.RELOAD_CERTS_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.SECURITY_CONFIG_UPDATE;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
public abstract class AbstractApiIntegrationTest extends RandomizedTest {

    public static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(
        new TestSecurityConfig.Role("all_access").clusterPermissions("*").indexPermissions("*").on("*")
    );
    public static final TestSecurityConfig.User REST_ADMIN_USER = new TestSecurityConfig.User("rest-api-admin").roles(
        new TestSecurityConfig.Role("role").clusterPermissions(allRestAdminPermissions())
    );

    public static final TestSecurityConfig.Role REST_ADMIN_REST_API_ACCESS_ROLE = new TestSecurityConfig.Role(
        "rest_admin__rest_api_access"
    );
    public static final TestSecurityConfig.Role EXAMPLE_ROLE = new TestSecurityConfig.Role("example_role").indexPermissions("crud")
        .on("example_index");

    /**
     * A user without any privileges
     */
    public static final TestSecurityConfig.User NEW_USER = new TestSecurityConfig.User("new-user");

    public static final String DEFAULT_PASSWORD = "secret";

    public static final ToXContentObject EMPTY_BODY = (builder, params) -> builder.startObject().endObject();

    public static final PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(
        Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT).build()
    );

    protected static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
            .nodeSettings(getClusterSettings())
            .authc(TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL)
            .users(ADMIN_USER, REST_ADMIN_USER, NEW_USER)
            .roles(EXAMPLE_ROLE, REST_ADMIN_REST_API_ACCESS_ROLE);
    }

    protected static Map<String, Object> getClusterSettings() {
        Map<String, Object> clusterSettings = new HashMap<>();
        clusterSettings.put(
            PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED,
            List.of("user_admin__all_access", REST_ADMIN_REST_API_ACCESS_ROLE.getName(), "user_rest-api-admin__role")
        );
        return clusterSettings;
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

    public static TestRestClient.HttpResponse badRequest(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_BAD_REQUEST));
        assertResponseBody(response.getBody());
        return response;
    }

    public static void forbidden(
        final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback,
        final String expectedMessage
    ) throws Exception {
        final var response = forbidden(endpointCallback);
        assertThat(response.getBody(), response.getTextFromJsonBody("/message"), is(expectedMessage));
    }

    public static TestRestClient.HttpResponse forbidden(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_FORBIDDEN));
        assertResponseBody(response.getBody());
        return response;
    }

    public static TestRestClient.HttpResponse notImplemented(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), is(HttpStatus.SC_NOT_IMPLEMENTED));
        assertResponseBody(response.getBody());
        return response;
    }

    public static TestRestClient.HttpResponse notFound(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_NOT_FOUND));
        assertResponseBody(response.getBody());
        return response;
    }

    public static TestRestClient.HttpResponse ok(final CheckedSupplier<TestRestClient.HttpResponse, Exception> endpointCallback)
        throws Exception {
        final var response = endpointCallback.get();
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_OK));
        assertResponseBody(response.getBody());
        return response;
    }

    public static void assertResponseBody(final String responseBody) {
        assertThat(responseBody, notNullValue());
        assertThat(responseBody, not(equalTo("")));
    }

    public static void assertResponseBody(final String responseBody, final String expectedMessage) {
        assertThat(responseBody, notNullValue());
        assertThat(responseBody, not(equalTo("")));
        assertThat(responseBody, containsString(expectedMessage));
    }

    public static ToXContentObject configJsonArray(final String... values) {
        return (builder, params) -> {
            builder.startArray();
            if (values != null) {
                for (final var v : values) {
                    if (v == null) {
                        builder.nullValue();
                    } else {
                        builder.value(v);
                    }
                }
            }
            return builder.endArray();
        };
    }

    static String[] generateArrayValues(boolean useNulls) {
        final var length = randomIntBetween(1, 5);
        final var values = new String[length];
        final var nullIndex = randomIntBetween(0, length - 1);
        for (var i = 0; i < values.length; i++) {
            if (useNulls && i == nullIndex) values[i] = null;
            else values[i] = randomAsciiAlphanumOfLength(10);
        }
        return values;
    }

    static ToXContentObject randomConfigArray(final boolean useNulls) {
        return useNulls
            ? configJsonArray(generateArrayValues(useNulls))
            : randomFrom(List.of(configJsonArray(generateArrayValues(false)), configJsonArray()));
    }

}
