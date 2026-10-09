/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.privileges.int_tests;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isInternalServerError;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class DlsRoleValidationIntTests {
    private static final String ROLE = "dls_probe";
    private static final String PATH = "_plugins/_security/api/roles/" + ROLE;
    private static final String VALID_DLS = "{\"match_none\":{}}";
    private static final List<String> INVALID_DLS = List.of(
        "{",
        "{\"term\"\": {\n",
        "{\"unknown_query\":{}}",
        "{\"query\":{\"match_none\":{}}}",
        "{}",
        " ",
        "{\"match_none\":{}} trailing",
        "{\"match_none\":{}} {\"match_all\":{}}"
    );
    private static final TestSecurityConfig.User USER = new TestSecurityConfig.User("dls_probe_user").roles(
        new TestSecurityConfig.Role(ROLE).isPredefined(true)
    );
    private static final TestSecurityConfig.User STORED_INVALID_USER = new TestSecurityConfig.User("stored_invalid_user").roles(
        new TestSecurityConfig.Role("stored_invalid").indexPermissions("read").dls("{").on("dls-probe")
    );
    private static final TestSecurityConfig.User STORED_TRAILING_TEXT_USER = new TestSecurityConfig.User("stored_trailing_text").roles(
        new TestSecurityConfig.Role("stored_trailing_text").indexPermissions("read").dls(VALID_DLS + " trailing").on("dls-probe")
    );
    private static final TestSecurityConfig.User STORED_TRAILING_QUERY_USER = new TestSecurityConfig.User("stored_trailing_query").roles(
        new TestSecurityConfig.Role("stored_trailing_query").indexPermissions("read").dls(VALID_DLS + " {\"match_all\":{}}").on("dls-probe")
    );

    @ClassRule
    public static final ClusterConfig.ClusterInstances CLUSTERS = new ClusterConfig.ClusterInstances(
        () -> new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USER, STORED_INVALID_USER, STORED_TRAILING_TEXT_USER, STORED_TRAILING_QUERY_USER)
            .indices(TestIndex.name("dls-probe").documentCount(2).seed(1).build())
    );

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> parameters() {
        return List.of(
            new Object[] { ClusterConfig.LEGACY_PRIVILEGES_EVALUATION },
            new Object[] { ClusterConfig.V4_PRIVILEGES_EVALUATION }
        );
    }

    private final LocalCluster cluster;

    public DlsRoleValidationIntTests(ClusterConfig config) {
        this.cluster = CLUSTERS.get(config);
    }

    private String role(Object dls) throws Exception {
        return DefaultObjectMapper.objectMapper()
            .writeValueAsString(
                Map.of(
                    "index_permissions",
                    List.of(Map.of("index_patterns", List.of("dls-probe"), "allowed_actions", List.of("read"), "dls", dls))
                )
            );
    }

    @Test
    public void invalidCreateIsRejectedWithoutSavingRole() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            for (String clause : INVALID_DLS) {
                var response = admin.putJson(PATH, role(clause));
                assertThat(response, isBadRequest());
                assertTrue(response.getBody().contains("index_permissions[0].dls"));
                assertThat(admin.get(PATH), isNotFound());
            }
        }
    }

    @Test
    public void malformedOuterJsonIsRejected() {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            var response = admin.putJson(PATH, """
                {"index_permissions":[{"index_patterns":["dls-probe"],"dls":"{"term"": {",
                "allowed_actions":["read"]}]}
                """);
            assertThat(response, isBadRequest());
            assertThat(admin.get(PATH), isNotFound());
        }
    }

    @Test
    public void invalidMultiRolePatchDoesNotSaveOtherChanges() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            assertThat(admin.putJson(PATH, role(VALID_DLS)), isCreated());
            try {
                String patch = DefaultObjectMapper.objectMapper()
                    .writeValueAsString(
                        List.of(
                            Map.of(
                                "op",
                                "add",
                                "path",
                                "/other_dls_probe",
                                "value",
                                DefaultObjectMapper.objectMapper().readTree(role(VALID_DLS))
                            ),
                            Map.of("op", "replace", "path", "/" + ROLE + "/index_permissions/0/dls", "value", "{")
                        )
                    );
                var response = admin.patch("_plugins/_security/api/roles", patch);
                assertThat(response, isBadRequest());
                assertThat(admin.get("_plugins/_security/api/roles/other_dls_probe"), isNotFound());
                assertRestricted(admin);
            } finally {
                admin.delete(PATH);
                admin.delete("_plugins/_security/api/roles/other_dls_probe");
            }
        }
    }

    @Test
    public void invalidUpdatePreservesExistingRestriction() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            assertThat(admin.putJson(PATH, role(VALID_DLS)), isCreated());
            try {
                for (String clause : INVALID_DLS) {
                    assertThat(admin.putJson(PATH, role(clause)), isBadRequest());
                    assertRestricted(admin);
                }
            } finally {
                admin.delete(PATH);
            }
        }
    }

    @Test
    public void invalidPatchPreservesExistingRestriction() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            assertThat(admin.putJson(PATH, role(VALID_DLS)), isCreated());
            try {
                for (String endpoint : List.of(PATH, "_plugins/_security/api/roles")) {
                    String path = endpoint.equals(PATH) ? "/index_permissions/0/dls" : "/" + ROLE + "/index_permissions/0/dls";
                    for (String clause : INVALID_DLS) {
                        String patch = DefaultObjectMapper.objectMapper()
                            .writeValueAsString(List.of(Map.of("op", "replace", "path", path, "value", clause)));
                        var response = admin.patch(endpoint, patch);
                        assertThat(response, isBadRequest());
                        assertRestricted(admin);
                    }
                }
            } finally {
                admin.delete(PATH);
            }
        }
    }

    @Test
    public void trailingWhitespaceIsAcceptedOnPutAndPatch() throws Exception {
        String dls = VALID_DLS + " \n\t";
        try (TestRestClient admin = cluster.getAdminCertRestClient(); TestRestClient user = cluster.getRestClient(USER)) {
            try {
                assertThat(admin.putJson(PATH, role(dls)), isCreated());
                for (String endpoint : List.of(PATH, "_plugins/_security/api/roles")) {
                    String path = endpoint.equals(PATH) ? "/index_permissions/0/dls" : "/" + ROLE + "/index_permissions/0/dls";
                    String patch = DefaultObjectMapper.objectMapper()
                        .writeValueAsString(List.of(Map.of("op", "replace", "path", path, "value", dls)));
                    assertThat(admin.patch(endpoint, patch), isOk());
                    var response = user.get("dls-probe/_search");
                    assertThat(response, isOk());
                    assertEquals(0, response.getIntFromJsonBody("/hits/total/value"));
                }
            } finally {
                admin.delete(PATH);
            }
        }
    }

    @Test
    public void storedDlsWithTrailingInputFailsClosed() {
        for (var account : List.of(STORED_TRAILING_TEXT_USER, STORED_TRAILING_QUERY_USER)) {
            try (TestRestClient user = cluster.getRestClient(account)) {
                var response = user.get("dls-probe/_search");
                assertThat(response, isInternalServerError());
                assertEquals("security_exception", response.getTextFromJsonBody("/error/type"));
            }
        }
    }

    private void assertRestricted(TestRestClient admin) {
        assertEquals(VALID_DLS, admin.get(PATH).getTextFromJsonBody("/" + ROLE + "/index_permissions/0/dls"));
        try (TestRestClient user = cluster.getRestClient(USER)) {
            var response = user.get("dls-probe/_search");
            assertThat(response, isOk());
            assertEquals(0, response.getIntFromJsonBody("/hits/total/value"));
        }
    }

    @Test
    public void nonStringDlsIsRejected() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient()) {
            for (Object value : List.of(Map.of("match_none", Map.of()), List.of(), 42, true)) {
                assertThat(admin.putJson(PATH, role(value)), isBadRequest());
                assertThat(admin.get(PATH), isNotFound());
            }
        }
    }

    @Test
    public void invalidStoredDlsFailsClosed() {
        try (TestRestClient user = cluster.getRestClient(STORED_INVALID_USER)) {
            var response = user.get("dls-probe/_search");
            assertThat(response, isInternalServerError());
            assertEquals("security_exception", response.getTextFromJsonBody("/error/type"));
        }
    }

    @Test
    public void templatesRemainSupportedAndMalformedTemplatesFailClosed() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient(); TestRestClient user = cluster.getRestClient(USER)) {
            for (String template : List.of(
                "{\"term\":{\"attr_keyword\":\"${user.name}\"}}",
                "{\"terms\":{\"attr_keyword\":[${user.roles}]}}"
            )) {
                try {
                    assertThat(admin.putJson(PATH, role(template)), isCreated());
                    var response = user.get("dls-probe/_search");
                    assertThat(response, isOk());
                    assertEquals(0, response.getIntFromJsonBody("/hits/total/value"));
                } finally {
                    admin.delete(PATH);
                }
            }
            try {
                assertThat(admin.putJson(PATH, role("{\"term\":{\"attr_keyword\":\"${user.name}\"}")), isCreated());
                assertThat(user.get("dls-probe/_search"), isInternalServerError());
            } finally {
                admin.delete(PATH);
            }
        }
    }

    @Test
    public void emptyStringStillExplicitlyRemovesDls() throws Exception {
        try (TestRestClient admin = cluster.getAdminCertRestClient(); TestRestClient user = cluster.getRestClient(USER)) {
            try {
                assertThat(admin.putJson(PATH, role(VALID_DLS)), isCreated());
                assertThat(admin.putJson(PATH, role("")), isOk());
                var response = user.get("dls-probe/_search");
                assertThat(response, isOk());
                assertEquals(2, response.getIntFromJsonBody("/hits/total/value"));
            } finally {
                admin.delete(PATH);
            }
        }
    }
}
