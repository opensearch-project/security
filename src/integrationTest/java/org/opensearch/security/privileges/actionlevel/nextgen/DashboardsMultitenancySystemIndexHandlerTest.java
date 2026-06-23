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
package org.opensearch.security.privileges.actionlevel.nextgen;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.DashboardsMultiTenancyConfiguration;
import org.opensearch.security.privileges.IndicesRequestResolver;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.TenantPrivileges;
import org.opensearch.security.user.User;
import org.opensearch.security.util.MockIndexMetadataBuilder;
import org.opensearch.transport.client.Client;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isForbidden;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.reason;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DashboardsMultitenancySystemIndexHandlerTest {
    final static ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE)
        .metadata(MockIndexMetadataBuilder.indices(".kibana").build())
        .build();
    final static ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
    final static IndexNameExpressionResolver resolver = new IndexNameExpressionResolver(threadContext);
    final static SearchRequest searchRequest = new SearchRequest(".kibana");

    @Test
    public void handle_multitenancyDisabled() {

        DashboardsMultitenancySystemIndexHandler subject = new DashboardsMultitenancySystemIndexHandler(
            () -> clusterState,
            mock(Client.class),
            threadContext,
            () -> TenantPrivileges.EMPTY,
            () -> new DashboardsMultiTenancyConfiguration(new org.opensearch.security.securityconf.impl.v7.ConfigV7.Kibana() {
                {
                    multitenancy_enabled = false;
                }
            })
        );

        ActionRequestMetadata<?, ?> actionRequestMetadata = mock(ActionRequestMetadata.class);
        when(actionRequestMetadata.resolvedIndices()).thenReturn(ResolvedIndices.of(".kibana"));

        User user = new User("test_user");

        PrivilegesEvaluationContext ctx = new PrivilegesEvaluationContext(
            user,
            ImmutableSet.of(),
            "indices:data/read/search",
            searchRequest,
            actionRequestMetadata,
            null,
            resolver,
            new IndicesRequestResolver(resolver),
            () -> clusterState,
            ActionPrivileges.EMPTY
        );

        assertNull(subject.handle(searchRequest, "indices:data/read/search", user, ctx));
    }

    @Test
    public void handle_privateTenantDisabled() {
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE)
            .metadata(MockIndexMetadataBuilder.indices(".kibana").build())
            .build();

        DashboardsMultitenancySystemIndexHandler subject = new DashboardsMultitenancySystemIndexHandler(
            () -> clusterState,
            mock(Client.class),
            threadContext,
            () -> TenantPrivileges.EMPTY,
            () -> new DashboardsMultiTenancyConfiguration(new org.opensearch.security.securityconf.impl.v7.ConfigV7.Kibana() {
                {
                    multitenancy_enabled = true;
                    private_tenant_enabled = false;
                }
            })
        );

        User user = new User("test_user").withRequestedTenant("__user__");

        ActionRequestMetadata<?, ?> actionRequestMetadata = mock(ActionRequestMetadata.class);
        when(actionRequestMetadata.resolvedIndices()).thenReturn(ResolvedIndices.of(".kibana"));

        PrivilegesEvaluationContext ctx = new PrivilegesEvaluationContext(
            user,
            ImmutableSet.of(),
            "indices:data/read/search",
            searchRequest,
            actionRequestMetadata,
            null,
            resolver,
            new IndicesRequestResolver(resolver),
            () -> clusterState,
            ActionPrivileges.EMPTY
        );

        PrivilegesEvaluatorResponse result = subject.handle(searchRequest, "indices:data/read/search", user, ctx);
        assertThat(result, isForbidden(reason("private tenant feature is disabled")));
    }

    @Test
    public void handle_dashboardsServerUser() {
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE)
            .metadata(MockIndexMetadataBuilder.indices(".kibana").build())
            .build();

        DashboardsMultitenancySystemIndexHandler subject = new DashboardsMultitenancySystemIndexHandler(
            () -> clusterState,
            mock(Client.class),
            threadContext,
            () -> TenantPrivileges.EMPTY,
            () -> new DashboardsMultiTenancyConfiguration(new org.opensearch.security.securityconf.impl.v7.ConfigV7.Kibana() {
                {
                    server_username = "dashboards_server";
                }
            })
        );

        User user = new User("dashboards_server").withRequestedTenant("__user__");

        ActionRequestMetadata<?, ?> actionRequestMetadata = mock(ActionRequestMetadata.class);
        when(actionRequestMetadata.resolvedIndices()).thenReturn(ResolvedIndices.of(".kibana"));

        PrivilegesEvaluationContext ctx = new PrivilegesEvaluationContext(
            user,
            ImmutableSet.of(),
            "indices:data/read/search",
            searchRequest,
            actionRequestMetadata,
            null,
            resolver,
            new IndicesRequestResolver(resolver),
            () -> clusterState,
            ActionPrivileges.EMPTY
        );

        PrivilegesEvaluatorResponse result = subject.handle(searchRequest, "indices:data/read/search", user, ctx);
        // The dashboards server user should be ignored by the multitenancy handler and get normal privilege evaluation
        assertThat(result, is(nullValue()));
    }

    @Test
    public void aliasOfIndex() {
        String dashboardsBase = ".kibana";
        String backingIndex = ".kibana_000001";

        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE)
            .metadata(MockIndexMetadataBuilder.indices(backingIndex).alias(dashboardsBase).of(backingIndex).build())
            .build();

        DashboardsMultitenancySystemIndexHandler handler = new DashboardsMultitenancySystemIndexHandler(
            () -> clusterState,
            mock(Client.class),
            new ThreadContext(Settings.EMPTY),
            () -> TenantPrivileges.EMPTY,
            () -> DashboardsMultiTenancyConfiguration.DEFAULT
        );

        assertEquals(dashboardsBase, handler.aliasOfIndex(backingIndex, dashboardsBase));
        assertNull(handler.aliasOfIndex("nonexistent", dashboardsBase));
    }

    @Test
    public void handle_unsupportedRequest() {
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE)
            .metadata(MockIndexMetadataBuilder.indices(".kibana").build())
            .build();

        DashboardsMultitenancySystemIndexHandler subject = new DashboardsMultitenancySystemIndexHandler(
            () -> clusterState,
            mock(Client.class),
            threadContext,
            () -> TenantPrivileges.EMPTY,
            () -> new DashboardsMultiTenancyConfiguration(new org.opensearch.security.securityconf.impl.v7.ConfigV7.Kibana() {
                {
                    multitenancy_enabled = true;
                }
            })
        );

        User user = new User("test_user").withRequestedTenant("__user__");

        ActionRequestMetadata<?, ?> actionRequestMetadata = mock(ActionRequestMetadata.class);
        when(actionRequestMetadata.resolvedIndices()).thenReturn(ResolvedIndices.of(".kibana"));

        org.opensearch.action.ActionRequest unsupportedRequest = mock(org.opensearch.action.ActionRequest.class);

        PrivilegesEvaluationContext ctx = new PrivilegesEvaluationContext(
            user,
            ImmutableSet.of(),
            "indices:data/read/search",
            unsupportedRequest,
            actionRequestMetadata,
            null,
            resolver,
            new IndicesRequestResolver(resolver),
            () -> clusterState,
            ActionPrivileges.EMPTY
        );

        PrivilegesEvaluatorResponse result = subject.handle(unsupportedRequest, "indices:data/read/search", user, ctx);
        assertThat(result, isForbidden(reason("Request is not supported by OpenSearch Dashboards multitenancy handler.")));
    }
}
