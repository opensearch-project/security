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

package org.opensearch.security.action.apitokens;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.cluster.service.ClusterService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

public class ApiTokenActionTest {

    private final ApiTokenAction apiTokenAction = new ApiTokenAction(mock(ClusterService.class), null, null);

    @Test
    public void testCreateIndexPermission() {
        Map<String, Object> validPermission = new HashMap<>();
        validPermission.put("index_pattern", "test-*");
        validPermission.put("allowed_actions", List.of("read"));

        ApiToken.IndexPermission result = apiTokenAction.createIndexPermission(validPermission);

        assertThat(result.getIndexPatterns(), is(List.of("test-*")));
        assertThat(result.getAllowedActions(), is(List.of("read")));
    }

    @Test
    public void testValidateRequestParameters() {
        Map<String, Object> validRequest = new HashMap<>();
        validRequest.put("name", "test-token");
        validRequest.put("cluster_permissions", Arrays.asList("perm1", "perm2"));
        apiTokenAction.validateRequestParameters(validRequest);

        // Missing name
        Map<String, Object> missingName = new HashMap<>();
        assertThrows(IllegalArgumentException.class, () -> apiTokenAction.validateRequestParameters(missingName));

        // Invalid cluster_permissions type
        Map<String, Object> invalidClusterPerms = new HashMap<>();
        invalidClusterPerms.put("name", "test");
        invalidClusterPerms.put("cluster_permissions", "not a list");
        assertThrows(IllegalArgumentException.class, () -> apiTokenAction.validateRequestParameters(invalidClusterPerms));
    }

    @Test
    public void testValidateIndexPermissionsList() {
        Map<String, Object> validPerm = new HashMap<>();
        validPerm.put("index_pattern", "test-*");
        validPerm.put("allowed_actions", List.of("read"));
        apiTokenAction.validateIndexPermissionsList(Collections.singletonList(validPerm));

        // Missing index_pattern
        Map<String, Object> missingPattern = new HashMap<>();
        missingPattern.put("allowed_actions", List.of("read"));
        assertThrows(
            IllegalArgumentException.class,
            () -> apiTokenAction.validateIndexPermissionsList(Collections.singletonList(missingPattern))
        );

        // Missing allowed_actions
        Map<String, Object> missingActions = new HashMap<>();
        missingActions.put("index_pattern", "test-*");
        assertThrows(
            IllegalArgumentException.class,
            () -> apiTokenAction.validateIndexPermissionsList(Collections.singletonList(missingActions))
        );

        // Invalid index_pattern type
        Map<String, Object> invalidPattern = new HashMap<>();
        invalidPattern.put("index_pattern", 123);
        invalidPattern.put("allowed_actions", List.of("read"));
        assertThrows(
            IllegalArgumentException.class,
            () -> apiTokenAction.validateIndexPermissionsList(Collections.singletonList(invalidPattern))
        );
    }

    @Test
    public void testExtractClusterPermissions() {
        Map<String, Object> requestBody = new HashMap<>();

        assertThat(apiTokenAction.extractClusterPermissions(requestBody), is(empty()));

        requestBody.put("cluster_permissions", Arrays.asList("perm1", "perm2"));
        assertThat(apiTokenAction.extractClusterPermissions(requestBody), is(Arrays.asList("perm1", "perm2")));
    }
}
