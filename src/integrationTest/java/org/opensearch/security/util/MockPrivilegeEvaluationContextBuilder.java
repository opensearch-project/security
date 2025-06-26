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

package org.opensearch.security.util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.IndicesRequestResolver;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.user.User;

/**
 * A utility test class that helps building PrivilegesEvaluationContext objects for testing.
 */
public class MockPrivilegeEvaluationContextBuilder {
    public static MockPrivilegeEvaluationContextBuilder ctx() {
        return new MockPrivilegeEvaluationContextBuilder();
    }

    private static final ClusterState EMPTY_CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE)
        .metadata(MockIndexMetadataBuilder.indices().build())
        .build();

    private String username = "test_user";
    private Map<String, String> attributes = new HashMap<>();
    private Set<String> roles = new HashSet<>();
    private ClusterState clusterState = EMPTY_CLUSTER_STATE;
    private ActionPrivileges actionPrivileges = ActionPrivileges.EMPTY;
    private String action;
    private ActionRequest request;

    public MockPrivilegeEvaluationContextBuilder attr(String key, String value) {
        this.attributes.put(key, value);
        return this;
    }

    public MockPrivilegeEvaluationContextBuilder clusterState(ClusterState clusterState) {
        this.clusterState = clusterState;
        return this;
    }

    public MockPrivilegeEvaluationContextBuilder indexMetadata(Metadata metadata) {
        return this.clusterState(ClusterState.builder(ClusterState.EMPTY_STATE).metadata(metadata).build());
    }

    public MockPrivilegeEvaluationContextBuilder roles(String... roles) {
        this.roles.addAll(Arrays.asList(roles));
        return this;
    }

    public MockPrivilegeEvaluationContextBuilder actionPrivileges(ActionPrivileges actionPrivileges) {
        this.actionPrivileges = actionPrivileges;
        return this;
    }

    public MockPrivilegeEvaluationContextBuilder action(String action) {
        this.action = action;
        return this;
    }

    public MockPrivilegeEvaluationContextBuilder request(ActionRequest request) {
        this.request = request;
        return this;
    }

    public PrivilegesEvaluationContext get() {
        IndexNameExpressionResolver indexNameExpressionResolver = new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY));

        User user = new User(this.username).withAttributes(ImmutableMap.copyOf(this.attributes));
        return new PrivilegesEvaluationContext(
            user,
            ImmutableSet.copyOf(roles),
            action,
            request,
            ActionRequestMetadata.empty(),
            null,
            indexNameExpressionResolver,
            new IndicesRequestResolver(indexNameExpressionResolver),
            () -> clusterState,
            this.actionPrivileges
        );
    }
}
