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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.util.List;
import java.util.function.Consumer;

import com.google.common.collect.ImmutableList;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import org.mockito.Mock;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class ConfigUpgradeApiActionUnitTest extends AbstractApiActionValidationTest {

    @Mock
    private Client client;

    @Mock
    private RestChannel restChannel;

    @Mock
    private RestRequest restRequest;

    private ConfigUpgradeApiAction configUpgradeApiAction;

    @Before
    public void setUp() throws IOException {
        setupRolesConfiguration();
        doReturn(XContentFactory.jsonBuilder()).when(restChannel).newBuilder();

        final var actionFuture = mock(ActionFuture.class);
        doReturn(mock(IndexResponse.class)).when(actionFuture).actionGet();
        doReturn(actionFuture).when(client).index(any());

        configUpgradeApiAction = spy(new ConfigUpgradeApiAction(clusterService, threadPool, securityApiDependencies));

        final var objectMapper = DefaultObjectMapper.objectMapper;
        final var config = objectMapper.createObjectNode();
        config.set("_meta", objectMapper.createObjectNode().put("type", CType.ROLES.toLCString()).put("config_version", 2));
        config.set("kibana_read_only", objectMapper.createObjectNode().put("reserved", true));
        final var newRole = objectMapper.createObjectNode();
        newRole.put("reserved", true);
        newRole.putArray("cluster_permissions").add("test-permission-1").add("test-permission-2");
        config.set("new_role", newRole);

        doReturn(config).when(configUpgradeApiAction).loadConfigFileAsJson(any());
    }

    @Test
    public void testCanUpgrade_ErrorLoadingConfig() throws Exception {
        // Setup
        doThrow(new IOException("abc")).when(configUpgradeApiAction).loadConfigFileAsJson(any());

        // Execute
        configUpgradeApiAction.canUpgrade(restChannel, restRequest, client);

        // Assert
        verify(restChannel).sendResponse(verifyResponseBody(body -> assertThat(body, containsString("see the log file to troubleshoot"))));
    }

    @Test
    public void testPerformUpgrade_ErrorLoadingConfig() throws Exception {
        // Setup
        doThrow(new IOException("abc")).when(configUpgradeApiAction).loadConfigFileAsJson(any());

        // Execute
        configUpgradeApiAction.performUpgrade(restChannel, restRequest, client);

        // Assert
        verify(restChannel).sendResponse(verifyResponseBody(body -> assertThat(body, containsString("see the log file to troubleshoot"))));
    }

    @Test
    public void testPerformUpgrade_ErrorApplyConfig() throws Exception {
        // Setup
        doThrow(new RuntimeException("abc")).when(configUpgradeApiAction).patchEntities(any(), any(), any());

        // Execute
        configUpgradeApiAction.performUpgrade(restChannel, restRequest, client);

        // Assert
        verify(restChannel).sendResponse(verifyResponseBody(body -> assertThat(body, containsString("see the log file to troubleshoot"))));
    }

    @Test
    public void testPerformUpgrade_NoDifferences() throws Exception {
        // Setup
        final var rolesCopy = rolesConfiguration.deepClone();
        rolesCopy.removeStatic(); // Statics are added by code, not by config files, they should be omitted
        final var rolesJsonNode = Utils.convertJsonToJackson(rolesCopy, true);
        doReturn(rolesJsonNode).when(configUpgradeApiAction).loadConfigFileAsJson(any());

        // Execute
        configUpgradeApiAction.performUpgrade(restChannel, restRequest, client);

        // Verify
        verify(restChannel).sendResponse(verifyResponseBody(body -> assertThat(body, containsString("no differences found"))));
    }

    @Test
    public void testPerformUpgrade_WithDifferences() throws Exception {
        // Execute
        configUpgradeApiAction.performUpgrade(restChannel, restRequest, client);

        // Verify
        verify(restChannel).sendResponse(argThat(response -> {
            final var rawResponseBody = response.content().utf8ToString();
            final var newlineNormalizedBody = rawResponseBody.replace("\r\n", "\n");
            assertThat(newlineNormalizedBody, equalTo("{\n" + //
                "  \"status\" : \"OK\",\n" + //
                "  \"upgrades\" : {\n" + //
                "    \"roles\" : {\n" + //
                "      \"add\" : [ \"new_role\" ]\n" + //
                "    }\n" + //
                "  }\n" + //
                "}"));
            return true;
        }));
    }

    @Test
    public void testConfigurationDifferences_OperationBash() throws IOException {
        final var testCases = new ImmutableList.Builder<ConfigUpgradeApiActionUnitTest.OperationTestCase>();

        testCases.add(
            new OperationTestCase("Missing entry", source -> {}, updated -> updated.put("a", "1"), List.of(List.of("add", "/a", "1")))
        );

        testCases.add(
            new OperationTestCase(
                "Same object",
                source -> source.set("a", objectMapper.createObjectNode()),
                updated -> updated.set("a", objectMapper.createObjectNode()),
                List.of()
            )
        );

        testCases.add(
            new OperationTestCase("Missing object", source -> source.set("a", objectMapper.createObjectNode()), updated -> {}, List.of())
        );

        testCases.add(new OperationTestCase("Moved and identical object", source -> {
            source.set("a", objectMapper.createObjectNode());
            source.set("b", objectMapper.createObjectNode());
            source.set("c", objectMapper.createObjectNode());
        }, updated -> {
            updated.set("a", objectMapper.createObjectNode());
            updated.set("c", objectMapper.createObjectNode());
            updated.set("b", objectMapper.createObjectNode());
        }, List.of()));

        testCases.add(new OperationTestCase("Moved and different object", source -> {
            source.set("a", objectMapper.createObjectNode());
            source.set("b", objectMapper.createObjectNode());
            source.set("c", objectMapper.createObjectNode());
        }, updated -> {
            updated.set("a", objectMapper.createObjectNode());
            updated.set("c", objectMapper.createObjectNode().put("d", "1"));
            updated.set("b", objectMapper.createObjectNode());
        }, List.of(List.of("add", "/c/d", "1"))));

        testCases.add(new OperationTestCase("Removed field object", source -> {
            source.set("a", objectMapper.createObjectNode().put("hidden", true));
            source.set("b", objectMapper.createObjectNode());
        }, updated -> {
            updated.set("a", objectMapper.createObjectNode());
            updated.set("b", objectMapper.createObjectNode());
        }, List.of(List.of("remove", "/a/hidden", "<NULL>"))));

        testCases.add(new OperationTestCase("Removed field object", source -> {
            final var roleA = objectMapper.createObjectNode();
            roleA.putArray("cluster_permissions").add("1").add("2").add("3");
            source.set("a", roleA);
        }, updated -> {
            final var roleA = objectMapper.createObjectNode();
            roleA.putArray("cluster_permissions").add("2").add("11").add("3").add("44");
            updated.set("a", roleA);
        },
            List.of(
                List.of("remove", "/a/cluster_permissions/0", "<NULL>"),
                List.of("add", "/a/cluster_permissions/1", "11"),
                List.of("add", "/a/cluster_permissions/3", "44")
            )
        ));

        for (final var tc : testCases.build()) {
            // Setup
            final var source = objectMapper.createObjectNode();
            source.set("_meta", objectMapper.createObjectNode().put("type", CType.ROLES.toLCString()).put("config_version", 2));
            tc.sourceChanges.accept(source);
            final var updated = objectMapper.createObjectNode();
            tc.updates.accept(updated);

            var sourceAsConfig = SecurityDynamicConfiguration.fromJson(objectMapper.writeValueAsString(source), CType.ROLES, 2, 1, 1);

            doReturn(ValidationResult.success(sourceAsConfig)).when(configUpgradeApiAction)
                .loadConfiguration(any(), anyBoolean(), anyBoolean());
            doReturn(updated).when(configUpgradeApiAction).loadConfigFileAsJson(any());

            // Execute
            var result = configUpgradeApiAction.computeDifferenceToUpdate(CType.ACTIONGROUPS);

            // Verify
            result.valid(differences -> {
                assertThat(differences.v1(), equalTo(CType.ACTIONGROUPS));
                assertThat(tc.name + ": Number of operations", differences.v2().size(), equalTo(tc.expectedResults.size()));
                final var expectedResultsIterator = tc.expectedResults.iterator();
                differences.v2().forEach(operation -> {
                    final List<String> expected = expectedResultsIterator.next();
                    assertThat(
                        tc.name + ": Operation type" + operation.toPrettyString(),
                        operation.get("op").asText(),
                        equalTo(expected.get(0))
                    );
                    assertThat(tc.name + ": Path" + operation.toPrettyString(), operation.get("path").asText(), equalTo(expected.get(1)));
                    assertThat(
                        tc.name + ": Value " + operation.toPrettyString(),
                        operation.has("value") ? operation.get("value").asText("<NULL>") : "<NULL>",
                        equalTo(expected.get(2))
                    );
                });
            });
        }
    }

    static class OperationTestCase {
        final String name;
        final Consumer<ObjectNode> sourceChanges;
        final Consumer<ObjectNode> updates;
        final List<List<String>> expectedResults;

        OperationTestCase(
            final String name,
            final Consumer<ObjectNode> sourceChanges,
            final Consumer<ObjectNode> updates,
            final List<List<String>> expectedResults
        ) {
            this.name = name;
            this.sourceChanges = sourceChanges;
            this.updates = updates;
            this.expectedResults = expectedResults;
        }

    }

    private RestResponse verifyResponseBody(final Consumer<String> test) {
        return argThat(response -> {
            final String content = response.content().utf8ToString();
            test.accept(content);
            return true;
        });
    }

}
