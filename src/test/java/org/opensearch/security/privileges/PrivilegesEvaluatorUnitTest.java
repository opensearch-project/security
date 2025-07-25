/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.util.List;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.action.apitokens.ApiTokenRepository;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.privileges.PrivilegesEvaluator.DNFOF_MATCHER;
import static org.opensearch.security.privileges.PrivilegesEvaluator.isClusterPerm;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PrivilegesEvaluatorUnitTest {

    private static final List<String> allowedDnfof = ImmutableList.of(
        "indices:admin/mappings/fields/get",
        "indices:admin/resolve/index",
        "indices:admin/shards/search_shards",
        "indices:data/read/explain",
        "indices:data/read/field_caps",
        "indices:data/read/get",
        "indices:data/read/mget",
        "indices:data/read/msearch",
        "indices:data/read/msearch/template",
        "indices:data/read/mtv",
        "indices:data/read/plugins/replication/file_chunk",
        "indices:data/read/plugins/replication/changes",
        "indices:data/read/scroll",
        "indices:data/read/scroll/clear",
        "indices:data/read/search",
        "indices:data/read/search/template",
        "indices:data/read/tv",
        "indices:monitor/settings/get",
        "indices:monitor/stats",
        "indices:admin/aliases/get"
    );

    private static final List<String> disallowedDnfof = ImmutableList.of(
        "indices:admin/aliases",
        "indices:admin/aliases/exists",
        "indices:admin/analyze",
        "indices:admin/cache/clear",
        "indices:admin/close",
        "indices:admin/create",
        "indices:admin/data_stream/create",
        "indices:admin/data_stream/delete",
        "indices:admin/data_stream/get",
        "indices:admin/delete",
        "indices:admin/exists",
        "indices:admin/flush",
        "indices:admin/forcemerge",
        "indices:admin/get",
        "indices:admin/mapping/put",
        "indices:admin/mappings/get",
        "indices:admin/open",
        "indices:admin/plugins/replication/index/setup/validate",
        "indices:admin/plugins/replication/index/start",
        "indices:admin/plugins/replication/index/pause",
        "indices:admin/plugins/replication/index/resume",
        "indices:admin/plugins/replication/index/stop",
        "indices:admin/plugins/replication/index/update",
        "indices:admin/plugins/replication/index/status_check",
        "indices:admin/refresh",
        "indices:admin/rollover",
        "indices:admin/seq_no/global_checkpoint_sync",
        "indices:admin/settings/update",
        "indices:admin/shrink",
        "indices:admin/synced_flush",
        "indices:admin/template/delete",
        "indices:admin/template/get",
        "indices:admin/template/put",
        "indices:admin/types/exists",
        "indices:admin/upgrade",
        "indices:admin/validate/query",
        "indices:data/write/bulk",
        "indices:data/write/delete",
        "indices:data/write/delete/byquery",
        "indices:data/write/plugins/replication/changes",
        "indices:data/write/index",
        "indices:data/write/reindex",
        "indices:data/write/update",
        "indices:data/write/update/byquery",
        "indices:monitor/data_stream/stats",
        "indices:monitor/recovery",
        "indices:monitor/segments",
        "indices:monitor/shard_stores",
        "indices:monitor/upgrade"
    );

    @Mock
    private ClusterService clusterService;

    @Mock
    private ThreadPool threadPool;

    @Mock
    private ConfigurationRepository configurationRepository;

    @Mock
    private IndexNameExpressionResolver resolver;

    @Mock
    private AuditLog auditLog;

    @Mock
    private PrivilegesInterceptor privilegesInterceptor;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    @Mock
    private IndexResolverReplacer irr;

    @Mock
    private NamedXContentRegistry namedXContentRegistry;

    @Mock
    private ClusterState clusterState;

    private Settings settings;
    private Supplier<ClusterState> clusterStateSupplier;
    private ThreadContext threadContext;
    private PrivilegesEvaluator privilegesEvaluator;

    @Before
    public void setUp() {
        settings = Settings.builder().build();
        clusterStateSupplier = () -> clusterState;
        threadContext = new ThreadContext(Settings.EMPTY);

        privilegesEvaluator = new PrivilegesEvaluator(
            clusterService,
            clusterStateSupplier,
            threadPool,
            threadContext,
            configurationRepository,
            resolver,
            auditLog,
            settings,
            privilegesInterceptor,
            clusterInfoHolder,
            irr,
            mock(ApiTokenRepository.class)
        );
    }

    @Test
    public void testClusterPerm() {
        String multiSearchTemplate = "indices:data/read/msearch/template";
        String monitorHealth = "cluster:monitor/health";
        String writeIndex = "indices:data/write/reindex";
        String adminClose = "indices:admin/close";
        String monitorUpgrade = "indices:monitor/upgrade";

        // Cluster Permissions
        assertTrue(isClusterPerm(multiSearchTemplate));
        assertTrue(isClusterPerm(writeIndex));
        assertTrue(isClusterPerm(monitorHealth));

        // Index Permissions
        assertFalse(isClusterPerm(adminClose));
        assertFalse(isClusterPerm(monitorUpgrade));
    }

    @Test
    public void testDnfofPermissions_negative() {
        for (final String permission : disallowedDnfof) {
            assertThat(DNFOF_MATCHER.test(permission), equalTo(false));
        }
    }

    @Test
    public void testDnfofPermissions_positive() {
        for (final String permission : allowedDnfof) {
            assertThat(DNFOF_MATCHER.test(permission), equalTo(true));
        }
    }

    @Test
    public void testEvaluate_NotInitialized_ExceptionThrown() {
        when(clusterInfoHolder.hasClusterManager()).thenReturn(true);
        OpenSearchSecurityException exception = assertThrows(
                OpenSearchSecurityException.class,
                () -> privilegesEvaluator.evaluate(null)
        );
        assertThat(exception.getMessage(), equalTo("OpenSearch Security is not initialized."));

        when(clusterInfoHolder.hasClusterManager()).thenReturn(false);
        exception = assertThrows(
                OpenSearchSecurityException.class,
                () -> privilegesEvaluator.evaluate(null)
        );
        assertThat(exception.getMessage(), equalTo("OpenSearch Security is not initialized. Cluster manager not present"));
    }
}
