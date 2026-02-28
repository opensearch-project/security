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

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.action.admin.cluster.shards.ClusterSearchShardsRequest;
import org.opensearch.action.bulk.BulkItemRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.logging.Loggers;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.NullAuditLog;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.RoleMapper;
import org.opensearch.security.privileges.actionlevel.SubjectBasedActionPrivileges;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.test.framework.log.LogsRule;

import com.selectivem.collections.CheckTable;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isAllowed;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isForbidden;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.reason;
import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.opensearch.security.util.MockPrivilegeEvaluationContextBuilder.ctx;
import static org.mockito.Mockito.when;

public class PrivilegesEvaluatorImplTest {
    @Rule
    public LogsRule logsRule = new LogsRule(PrivilegesEvaluatorImpl.class.getName());

    @Test
    public void evaluate_universallyDeniedActions() throws Exception {
        PrivilegesEvaluatorImpl subject = createSubject(
            Settings.builder()
                .putList(
                    "plugins.security.privileges_evaluation.actions.universally_denied_actions",
                    "cluster:allowed/but_denied/something"
                )
                .build()
        );
        assertThat(
            subject.evaluate(
                ctx().actionPrivileges(subject.getActionPrivileges()).roles("test_role").action("cluster:allowed/something").get()
            ),
            isAllowed()
        );
        assertThat(
            subject.evaluate(
                ctx().actionPrivileges(subject.getActionPrivileges())
                    .roles("test_role")
                    .action("cluster:allowed/but_denied/something")
                    .get()
            ),
            isForbidden()
        );
    }

    @Test
    public void evaluate_serviceAccountUserDenied() throws Exception {
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        assertThat(
            subject.evaluate(ctx().actionPrivileges(subject.getActionPrivileges()).roles("test_role").action("cluster:allowed/x").get()),
            isAllowed()
        );
        assertThat(
            subject.evaluate(
                ctx().actionPrivileges(subject.getActionPrivileges())
                    .roles("test_role")
                    .attr("attr.internal.service", "true")
                    .action("cluster:allowed/x")
                    .get()
            ),
            isForbidden(reason("User is a service account which does not have access to any cluster action"))
        );
    }

    @Test
    public void createContext_pluginUser() throws Exception {
        SubjectBasedActionPrivileges.PrivilegeSpecification pluginPrivileges = new SubjectBasedActionPrivileges.PrivilegeSpecification(
            SecurityDynamicConfiguration.fromYaml("""
                only_role:
                   cluster_permissions:
                   - 'cluster:allowed_for_plugin/*'
                """, CType.ROLES).getCEntry("only_role"),
            index -> false
        );
        PrivilegesEvaluatorImpl subject = createSubject(
            Settings.EMPTY,
            PrivilegesEvaluator.DynamicDependencies.EMPTY.with(Map.of("plugin:test", pluginPrivileges))
        );
        assertThat(subject.evaluate(subject.createContext(new User("plugin:test"), "cluster:allowed_for_plugin/x")), isAllowed());
        assertThat(subject.evaluate(subject.createContext(new User("plugin:test"), "cluster:allowed/x")), isForbidden());
    }

    @Test
    public void logPrivilegeEvaluationResult_allowed() throws Exception {
        Level initialLevel = LogManager.getLogger(PrivilegesEvaluatorImpl.class).getLevel();
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        SearchRequest request = new SearchRequest("index_a");
        PrivilegesEvaluationContext ctx = ctx().actionPrivileges(subject.getActionPrivileges())
            .action("indices:test/test")
            .request(request)
            .get();
        try {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), Level.DEBUG);
            subject.logPrivilegeEvaluationResult(ctx, PrivilegesEvaluatorResponse.ok(), "index");
            logsRule.assertThatContain("Allowing index action because all privileges are present.");
        } finally {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), initialLevel);
        }
    }

    @Test
    public void logPrivilegeEvaluationResult_allowedWithExceptions() throws Exception {
        Level initialLevel = LogManager.getLogger(PrivilegesEvaluatorImpl.class).getLevel();
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        SearchRequest request = new SearchRequest("index_a");
        PrivilegesEvaluationContext ctx = ctx().actionPrivileges(subject.getActionPrivileges())
            .action("indices:test/test")
            .request(request)
            .get();
        try {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), Level.DEBUG);
            subject.logPrivilegeEvaluationResult(
                ctx,
                PrivilegesEvaluatorResponse.ok()
                    .evaluationExceptions(List.of(new PrivilegesEvaluationException("Test evaluation exception", new RuntimeException()))),
                "index"
            );
            logsRule.assertThatContain("Allowing index action, but: There were errors during privilege evaluation");
        } finally {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), initialLevel);
        }
    }

    @Test
    public void logPrivilegeEvaluationResult_partiallyAllowed() throws Exception {
        Level initialLevel = LogManager.getLogger(PrivilegesEvaluatorImpl.class).getLevel();
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        SearchRequest request = new SearchRequest("index_a");
        PrivilegesEvaluationContext ctx = ctx().actionPrivileges(subject.getActionPrivileges())
            .action("indices:test/test")
            .request(request)
            .get();
        try {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), Level.DEBUG);
            CheckTable<String, String> checkTable = CheckTable.create(Set.of("index_a", "index_b"), "indices:test/test");
            checkTable.check("index_b", "indices:test/test");
            subject.logPrivilegeEvaluationResult(
                ctx,
                PrivilegesEvaluatorResponse.ok()
                    .reason("Only allowed for a sub-set of indices")
                    .originalResult(PrivilegesEvaluatorResponse.partiallyOk(checkTable.getCompleteRows(), checkTable)),
                "index"
            );
            logsRule.assertThatContain("Allowing index action, but: Only allowed for a sub-set of indices");
            logsRule.assertThatContain("index_a| MISSING");
        } finally {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), initialLevel);
        }
    }

    @Test
    public void logPrivilegeEvaluationResult_insufficient() throws Exception {
        Level initialLevel = LogManager.getLogger(PrivilegesEvaluatorImpl.class).getLevel();
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        SearchRequest request = new SearchRequest("index_a");
        PrivilegesEvaluationContext ctx = ctx().actionPrivileges(subject.getActionPrivileges())
            .action("indices:test/test")
            .request(request)
            .get();
        try {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), Level.DEBUG);
            subject.logPrivilegeEvaluationResult(
                ctx,
                PrivilegesEvaluatorResponse.insufficient("indices:test/test").reason("test reason"),
                "index"
            );
            logsRule.assertThatContain("Not allowing index action: test reason");
        } finally {
            Loggers.setLevel(LogManager.getLogger(PrivilegesEvaluatorImpl.class), initialLevel);
        }
    }

    @Test
    public void requiredIndexPermissions_defaultSearchRequest() throws Exception {
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        Set<String> result = subject.requiredIndexPermissions(new SearchRequest(), "indices:custom/action");
        assertThat(result, equalTo(Set.of("indices:custom/action")));
    }

    @Test
    public void requiredIndexPermissions_clusterSearchShardsRequest() throws Exception {
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        ClusterSearchShardsRequest request = new ClusterSearchShardsRequest();
        Set<String> result = subject.requiredIndexPermissions(request, "indices:search/shards");
        assertThat(result, equalTo(Set.of("indices:search/shards", SearchAction.NAME)));
    }

    @Test
    public void requiredIndexPermissions_bulkShardRequest() throws Exception {
        PrivilegesEvaluatorImpl subject = createSubject(Settings.EMPTY);
        BulkShardRequest request = Mockito.mock(BulkShardRequest.class);
        when(request.items()).thenReturn(new BulkItemRequest[] { new BulkItemRequest(0, new UpdateRequest("index_a", "1")) });

        Set<String> result = subject.requiredIndexPermissions(request, "indices:bulk/shard");
        assertThat(result, equalTo(Set.of("indices:bulk/shard", org.opensearch.action.update.UpdateAction.NAME)));
    }

    static PrivilegesEvaluatorImpl createSubject(Settings settings) throws Exception {
        return createSubject(settings, PrivilegesEvaluator.DynamicDependencies.EMPTY);
    }

    static PrivilegesEvaluatorImpl createSubject(Settings settings, PrivilegesEvaluator.DynamicDependencies dynamicDependencies)
        throws Exception {
        Metadata metadata = indices("index_a1", "index_a2", "index_b1", "index_b2").build();
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(metadata).build();
        RoleMapper roleMapper = (user, caller) -> user.getRoles();
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("""
            test_role:
               cluster_permissions:
               - 'cluster:allowed/*'
            """, CType.ROLES);

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        IndexNameExpressionResolver indexNameExpressionResolver = new IndexNameExpressionResolver(threadContext);

        return new PrivilegesEvaluatorImpl(
            new PrivilegesEvaluator.CoreDependencies(
                null,
                () -> clusterState,
                null,
                roleMapper,
                null,
                threadContext,
                new NullAuditLog(),
                settings,
                indexNameExpressionResolver,
                () -> "unavailable"
            ),
            dynamicDependencies.with(roles)
        );
    }
}
