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
package org.opensearch.security.privileges;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;

import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.unit.ByteSizeUnit;
import org.opensearch.core.common.unit.ByteSizeValue;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.security.util.MockIndexMetadataBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isAllowed;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isForbidden;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isPartiallyOk;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.missingPrivileges;
import static org.opensearch.security.util.MockIndexMetadataBuilder.dataStreams;
import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for ActionPrivileges. As the ActionPrivileges provides quite a few different code paths for checking
 * privileges with different performance characteristics, this test suite defines different test cases for making sure
 * all these code paths are tested. So, all functionality must be tested for "well-known" actions and non-well-known
 * actions. For index privileges, there are a couple of more tests dimensions. See below.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    ActionPrivilegesTest.ClusterPrivileges.class,
    ActionPrivilegesTest.IndexPrivileges.IndicesAndAliases.class,
    ActionPrivilegesTest.IndexPrivileges.DataStreams.class,
    ActionPrivilegesTest.Misc.class,
    ActionPrivilegesTest.StatefulIndexPrivilegesHeapSize.class })
public class ActionPrivilegesTest {
    public static class ClusterPrivileges {
        @Test
        public void wellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/stats*", CType.ROLES);

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(subject.hasClusterPrivilege(ctx("test_role"), "cluster:monitor/nodes/stats"), isAllowed());
            assertThat(
                subject.hasClusterPrivilege(ctx("other_role"), "cluster:monitor/nodes/stats"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/stats"))
            );
            assertThat(
                subject.hasClusterPrivilege(ctx("test_role"), "cluster:monitor/nodes/other"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/other"))
            );
        }

        @Test
        public void notWellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/stats*", CType.ROLES);

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(subject.hasClusterPrivilege(ctx("test_role"), "cluster:monitor/nodes/stats/somethingnotwellknown"), isAllowed());
            assertThat(
                subject.hasClusterPrivilege(ctx("other_role"), "cluster:monitor/nodes/stats/somethingnotwellknown"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/stats/somethingnotwellknown"))
            );
            assertThat(
                subject.hasClusterPrivilege(ctx("test_role"), "cluster:monitor/nodes/something/else"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/something/else"))
            );
        }

        @Test
        public void wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - '*'", CType.ROLES);

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(subject.hasClusterPrivilege(ctx("test_role"), "cluster:whatever"), isAllowed());
            assertThat(
                subject.hasClusterPrivilege(ctx("other_role"), "cluster:whatever"),
                isForbidden(missingPrivileges("cluster:whatever"))
            );
        }

        @Test
        public void explicit_wellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("non_explicit_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - '*'\n" + //
                "explicit_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/stats\n" + //
                "semi_explicit_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/stats*\n", //
                CType.ROLES
            );

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(subject.hasExplicitClusterPrivilege(ctx("explicit_role"), "cluster:monitor/nodes/stats"), isAllowed());
            assertThat(subject.hasExplicitClusterPrivilege(ctx("semi_explicit_role"), "cluster:monitor/nodes/stats"), isAllowed());
            assertThat(
                subject.hasExplicitClusterPrivilege(ctx("non_explicit_role"), "cluster:monitor/nodes/stats"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/stats"))
            );
            assertThat(
                subject.hasExplicitClusterPrivilege(ctx("other_role"), "cluster:monitor/nodes/stats"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/stats"))
            );
        }

        @Test
        public void explicit_notWellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("non_explicit_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - '*'\n" + //
                "explicit_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/notwellknown\n" + //
                "semi_explicit_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/*\n", //
                CType.ROLES
            );

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(subject.hasExplicitClusterPrivilege(ctx("explicit_role"), "cluster:monitor/nodes/notwellknown"), isAllowed());
            assertThat(subject.hasExplicitClusterPrivilege(ctx("semi_explicit_role"), "cluster:monitor/nodes/notwellknown"), isAllowed());
            assertThat(
                subject.hasExplicitClusterPrivilege(ctx("non_explicit_role"), "cluster:monitor/nodes/notwellknown"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/notwellknown"))
            );
            assertThat(
                subject.hasExplicitClusterPrivilege(ctx("other_role"), "cluster:monitor/nodes/notwellknown"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/notwellknown"))
            );
        }

        @Test
        public void hasAny_wellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/stats*", CType.ROLES);

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(subject.hasAnyClusterPrivilege(ctx("test_role"), ImmutableSet.of("cluster:monitor/nodes/stats")), isAllowed());
            assertThat(
                subject.hasAnyClusterPrivilege(
                    ctx("test_role"),
                    ImmutableSet.of("cluster:monitor/nodes/foo", "cluster:monitor/nodes/stats")
                ),
                isAllowed()
            );

            assertThat(
                subject.hasAnyClusterPrivilege(ctx("other_role"), ImmutableSet.of("cluster:monitor/nodes/stats")),
                isForbidden(missingPrivileges("cluster:monitor/nodes/stats"))
            );
            assertThat(
                subject.hasAnyClusterPrivilege(ctx("test_role"), ImmutableSet.of("cluster:monitor/nodes/other")),
                isForbidden(missingPrivileges("cluster:monitor/nodes/other"))
            );
        }

        @Test
        public void hasAny_notWellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - cluster:monitor/nodes/*", CType.ROLES);

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(
                subject.hasAnyClusterPrivilege(ctx("test_role"), ImmutableSet.of("cluster:monitor/nodes/notwellknown")),
                isAllowed()
            );
            assertThat(
                subject.hasAnyClusterPrivilege(
                    ctx("test_role"),
                    ImmutableSet.of("cluster:monitor/other", "cluster:monitor/nodes/notwellknown")
                ),
                isAllowed()
            );

            assertThat(
                subject.hasAnyClusterPrivilege(ctx("other_role"), ImmutableSet.of("cluster:monitor/nodes/notwellknown")),
                isForbidden(missingPrivileges("cluster:monitor/nodes/notwellknown"))
            );
            assertThat(
                subject.hasAnyClusterPrivilege(ctx("test_role"), ImmutableSet.of("cluster:monitor/other")),
                isForbidden(missingPrivileges("cluster:monitor/other"))
            );
            assertThat(
                subject.hasAnyClusterPrivilege(ctx("test_role"), ImmutableSet.of("cluster:monitor/other", "cluster:monitor/yetanother")),
                isForbidden()
            );
        }

        @Test
        public void hasAny_wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml("test_role:\n" + //
                "  cluster_permissions:\n" + //
                "  - '*'", CType.ROLES);

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null, Settings.EMPTY);

            assertThat(subject.hasAnyClusterPrivilege(ctx("test_role"), ImmutableSet.of("cluster:whatever")), isAllowed());

            assertThat(
                subject.hasAnyClusterPrivilege(ctx("other_role"), ImmutableSet.of("cluster:whatever")),
                isForbidden(missingPrivileges("cluster:whatever"))
            );
        }
    }

    /**
     * Tests for index privileges. This class contains two parameterized test suites, first for indices and aliases,
     * second for data streams.
     * <p>
     * Both test suites use parameters to create a 3-dimensional test case space to make sure all code paths are covered.
     * <p>
     * The dimensions are (see also the params() methods):
     * <ol>
     * <li>1. roles.yml; index patterns: Different usages of patterns, wildcards and constant names.
     * <li>2. roles.yml; action patterns: Well known actions vs non-well known actions combined with use of patterns vs use of constant action names
     * <li>3. Statefulness: Shall the data structures from ActionPrivileges.StatefulIndexPrivileges be used or not
     * </ol>
     * As so many different situations need to be tested, the test oracle method covers() is used to verify the results.
     */
    public static class IndexPrivileges {

        @RunWith(Parameterized.class)
        public static class IndicesAndAliases {
            final ActionSpec actionSpec;
            final IndexSpec indexSpec;
            final SecurityDynamicConfiguration<RoleV7> roles;
            final String primaryAction;
            final ImmutableSet<String> requiredActions;
            final ImmutableSet<String> otherActions;
            final ActionPrivileges subject;

            @Test
            public void positive_full() throws Exception {
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx("test_role"), requiredActions, resolved("index_a11"));
                assertThat(result, isAllowed());
            }

            @Test
            public void positive_partial() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, requiredActions, resolved("index_a11", "index_a12"));

                if (covers(ctx, "index_a11", "index_a12")) {
                    assertThat(result, isAllowed());
                } else if (covers(ctx, "index_a11")) {
                    assertThat(result, isPartiallyOk("index_a11"));
                } else {
                    assertThat(result, isForbidden(missingPrivileges(requiredActions)));
                }
            }

            @Test
            public void positive_partial2() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(
                    ctx,
                    requiredActions,
                    resolved("index_a11", "index_a12", "index_b1")
                );

                if (covers(ctx, "index_a11", "index_a12", "index_b1")) {
                    assertThat(result, isAllowed());
                } else if (covers(ctx, "index_a11", "index_a12")) {
                    assertThat(result, isPartiallyOk("index_a11", "index_a12"));
                } else if (covers(ctx, "index_a11")) {
                    assertThat(result, isPartiallyOk("index_a11"));
                } else {
                    assertThat(result, isForbidden(missingPrivileges(requiredActions)));
                }
            }

            @Test
            public void positive_noLocal() throws Exception {
                IndexResolverReplacer.Resolved resolved = new IndexResolverReplacer.Resolved(
                    ImmutableSet.of(),
                    ImmutableSet.of(),
                    ImmutableSet.of("remote:a"),
                    ImmutableSet.of("remote:a"),
                    IndicesOptions.LENIENT_EXPAND_OPEN
                );
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx("test_role"), requiredActions, resolved);
                assertThat(result, isAllowed());
            }

            @Test
            public void negative_wrongRole() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("other_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, requiredActions, resolved("index_a11"));
                assertThat(result, isForbidden(missingPrivileges(requiredActions)));
            }

            @Test
            public void negative_wrongAction() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, otherActions, resolved("index_a11"));

                if (actionSpec.givenPrivs.contains("*")) {
                    assertThat(result, isAllowed());
                } else {
                    assertThat(result, isForbidden(missingPrivileges(otherActions)));
                }
            }

            @Test
            public void positive_hasExplicit_full() {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(ctx, requiredActions, resolved("index_a11"));

                if (actionSpec.givenPrivs.contains("*")) {
                    // The * is forbidden for explicit privileges
                    assertThat(result, isForbidden(missingPrivileges(requiredActions)));
                } else if (!requiredActions.contains("indices:data/read/search")) {
                    // For test purposes, we have designated "indices:data/read/search" as an action requiring explicit privileges
                    // Other actions are not covered here
                    assertThat(result, isForbidden(missingPrivileges(requiredActions)));
                } else {
                    assertThat(result, isAllowed());
                }
            }

            private boolean covers(PrivilegesEvaluationContext ctx, String... indices) {
                for (String index : indices) {
                    if (!indexSpec.covers(ctx.getUser(), index)) {
                        return false;
                    }
                }
                return true;
            }

            @Parameterized.Parameters(name = "{0};  actions: {1};  {2}")
            public static Collection<Object[]> params() {
                List<Object[]> result = new ArrayList<>();

                for (IndexSpec indexSpec : Arrays.asList(
                    new IndexSpec().givenIndexPrivs("*"), //
                    new IndexSpec().givenIndexPrivs("index_*"), //
                    new IndexSpec().givenIndexPrivs("index_a11"), //
                    new IndexSpec().givenIndexPrivs("index_a1*"), //
                    new IndexSpec().givenIndexPrivs("index_${attrs.dept_no}"), //
                    new IndexSpec().givenIndexPrivs("alias_a1*") //
                )) {
                    for (ActionSpec actionSpec : Arrays.asList(
                        new ActionSpec("wildcard")//
                            .givenPrivs("*")
                            .requiredPrivs("indices:data/read/search"), //
                        new ActionSpec("constant, well known")//
                            .givenPrivs("indices:data/read/search")
                            .requiredPrivs("indices:data/read/search"), //
                        new ActionSpec("pattern, well known")//
                            .givenPrivs("indices:data/read/*")
                            .requiredPrivs("indices:data/read/search"), //
                        new ActionSpec("pattern, well known, two required privs")//
                            .givenPrivs("indices:data/read/*")
                            .requiredPrivs("indices:data/read/search", "indices:data/read/get"), //
                        new ActionSpec("constant, non well known")//
                            .givenPrivs("indices:unknown/unwell")
                            .requiredPrivs("indices:unknown/unwell"), //
                        new ActionSpec("pattern, non well known")//
                            .givenPrivs("indices:unknown/*")
                            .requiredPrivs("indices:unknown/unwell"), //
                        new ActionSpec("pattern, non well known, two required privs")//
                            .givenPrivs("indices:unknown/*")
                            .requiredPrivs("indices:unknown/unwell", "indices:unknown/notatall")//

                    )) {
                        for (Statefulness statefulness : Statefulness.values()) {
                            result.add(new Object[] { indexSpec, actionSpec, statefulness });
                        }
                    }
                }
                return result;
            }

            public IndicesAndAliases(IndexSpec indexSpec, ActionSpec actionSpec, Statefulness statefulness) throws Exception {
                this.indexSpec = indexSpec;
                this.actionSpec = actionSpec;
                this.roles = indexSpec.toRolesConfig(actionSpec);

                this.primaryAction = actionSpec.primaryAction;
                this.requiredActions = actionSpec.requiredPrivs;

                this.otherActions = actionSpec.wellKnownActions
                    ? ImmutableSet.of("indices:data/write/update")
                    : ImmutableSet.of("indices:foobar/unknown");
                this.indexSpec.indexMetadata = INDEX_METADATA;

                Settings settings = Settings.EMPTY;
                if (statefulness == Statefulness.STATEFUL_LIMITED) {
                    settings = Settings.builder()
                        .put(ActionPrivileges.PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE.getKey(), new ByteSizeValue(10, ByteSizeUnit.BYTES))
                        .build();
                }

                this.subject = new ActionPrivileges(
                    roles,
                    FlattenedActionGroups.EMPTY,
                    () -> INDEX_METADATA,
                    settings,
                    WellKnownActions.CLUSTER_ACTIONS,
                    WellKnownActions.INDEX_ACTIONS,
                    WellKnownActions.INDEX_ACTIONS
                );

                if (statefulness == Statefulness.STATEFUL || statefulness == Statefulness.STATEFUL_LIMITED) {
                    this.subject.updateStatefulIndexPrivileges(INDEX_METADATA, 1);
                }
            }

            final static Map<String, IndexAbstraction> INDEX_METADATA = //
                indices("index_a11", "index_a12", "index_a21", "index_a22", "index_b1", "index_b2")//
                    .alias("alias_a")
                    .of("index_a11", "index_a12", "index_a21", "index_a22")//
                    .alias("alias_a1")
                    .of("index_a11", "index_a12")//
                    .alias("alias_a2")
                    .of("index_a21", "index_a22")//
                    .alias("alias_b")
                    .of("index_b1", "index_b2")//
                    .build()
                    .getIndicesLookup();

            static IndexResolverReplacer.Resolved resolved(String... indices) {
                return new IndexResolverReplacer.Resolved(
                    ImmutableSet.of(),
                    ImmutableSet.copyOf(indices),
                    ImmutableSet.copyOf(indices),
                    ImmutableSet.of(),
                    IndicesOptions.LENIENT_EXPAND_OPEN
                );
            }
        }

        @RunWith(Parameterized.class)
        public static class DataStreams {
            final ActionSpec actionSpec;
            final IndexSpec indexSpec;
            final SecurityDynamicConfiguration<RoleV7> roles;
            final String primaryAction;
            final ImmutableSet<String> requiredActions;
            final ImmutableSet<String> otherActions;
            final ActionPrivileges subject;

            @Test
            public void positive_full() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, requiredActions, resolved("data_stream_a11"));
                if (covers(ctx, "data_stream_a11")) {
                    assertThat(result, isAllowed());
                } else if (covers(ctx, ".ds-data_stream_a11-000001")) {
                    assertThat(
                        result,
                        isPartiallyOk(".ds-data_stream_a11-000001", ".ds-data_stream_a11-000002", ".ds-data_stream_a11-000003")
                    );
                } else {
                    assertThat(result, isForbidden(missingPrivileges(requiredActions)));
                }
            }

            @Test
            public void positive_partial() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(
                    ctx,
                    requiredActions,
                    resolved("data_stream_a11", "data_stream_a12")
                );

                if (covers(ctx, "data_stream_a11", "data_stream_a12")) {
                    assertThat(result, isAllowed());
                } else if (covers(ctx, "data_stream_a11")) {
                    assertThat(
                        result,
                        isPartiallyOk(
                            "data_stream_a11",
                            ".ds-data_stream_a11-000001",
                            ".ds-data_stream_a11-000002",
                            ".ds-data_stream_a11-000003"
                        )
                    );
                } else if (covers(ctx, ".ds-data_stream_a11-000001")) {
                    assertThat(
                        result,
                        isPartiallyOk(".ds-data_stream_a11-000001", ".ds-data_stream_a11-000002", ".ds-data_stream_a11-000003")
                    );
                } else {
                    assertThat(result, isForbidden(missingPrivileges(requiredActions)));
                }
            }

            @Test
            public void negative_wrongRole() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("other_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, requiredActions, resolved("data_stream_a11"));
                assertThat(result, isForbidden(missingPrivileges(requiredActions)));
            }

            @Test
            public void negative_wrongAction() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, otherActions, resolved("data_stream_a11"));
                assertThat(result, isForbidden(missingPrivileges(otherActions)));
            }

            private boolean covers(PrivilegesEvaluationContext ctx, String... indices) {
                for (String index : indices) {
                    if (!indexSpec.covers(ctx.getUser(), index)) {
                        return false;
                    }
                }
                return true;
            }

            @Parameterized.Parameters(name = "{0};  actions: {1};  {2}")
            public static Collection<Object[]> params() {
                List<Object[]> result = new ArrayList<>();

                for (IndexSpec indexSpec : Arrays.asList(
                    new IndexSpec().givenIndexPrivs("*"), //
                    new IndexSpec().givenIndexPrivs("data_stream_*"), //
                    new IndexSpec().givenIndexPrivs("data_stream_a11"), //
                    new IndexSpec().givenIndexPrivs("data_stream_a1*"), //
                    new IndexSpec().givenIndexPrivs("data_stream_${attrs.dept_no}"), //
                    new IndexSpec().givenIndexPrivs(".ds-data_stream_a11*") //
                )) {
                    for (ActionSpec actionSpec : Arrays.asList(
                        new ActionSpec("constant, well known")//
                            .givenPrivs("indices:data/read/search")
                            .requiredPrivs("indices:data/read/search"), //
                        new ActionSpec("pattern, well known")//
                            .givenPrivs("indices:data/read/*")
                            .requiredPrivs("indices:data/read/search"), //
                        new ActionSpec("pattern, well known, two required privs")//
                            .givenPrivs("indices:data/read/*")
                            .requiredPrivs("indices:data/read/search", "indices:data/read/get"), //
                        new ActionSpec("constant, non well known")//
                            .givenPrivs("indices:unknown/unwell")
                            .requiredPrivs("indices:unknown/unwell"), //
                        new ActionSpec("pattern, non well known")//
                            .givenPrivs("indices:unknown/*")
                            .requiredPrivs("indices:unknown/unwell"), //
                        new ActionSpec("pattern, non well known, two required privs")//
                            .givenPrivs("indices:unknown/*")
                            .requiredPrivs("indices:unknown/unwell", "indices:unknown/notatall")//

                    )) {
                        for (Statefulness statefulness : Statefulness.values()) {
                            result.add(new Object[] { indexSpec, actionSpec, statefulness });
                        }
                    }
                }
                return result;
            }

            public DataStreams(IndexSpec indexSpec, ActionSpec actionSpec, Statefulness statefulness) throws Exception {
                this.indexSpec = indexSpec;
                this.actionSpec = actionSpec;
                this.roles = indexSpec.toRolesConfig(actionSpec);

                this.primaryAction = actionSpec.primaryAction;
                this.requiredActions = actionSpec.requiredPrivs;

                this.otherActions = actionSpec.wellKnownActions
                    ? ImmutableSet.of("indices:data/write/update")
                    : ImmutableSet.of("indices:foobar/unknown");
                this.indexSpec.indexMetadata = INDEX_METADATA;

                Settings settings = Settings.EMPTY;
                if (statefulness == Statefulness.STATEFUL_LIMITED) {
                    settings = Settings.builder()
                        .put(ActionPrivileges.PRECOMPUTED_PRIVILEGES_MAX_HEAP_SIZE.getKey(), new ByteSizeValue(10, ByteSizeUnit.BYTES))
                        .build();
                }

                this.subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, () -> INDEX_METADATA, settings);

                if (statefulness == Statefulness.STATEFUL || statefulness == Statefulness.STATEFUL_LIMITED) {
                    this.subject.updateStatefulIndexPrivileges(INDEX_METADATA, 1);
                }
            }

            final static Map<String, IndexAbstraction> INDEX_METADATA = //
                dataStreams("data_stream_a11", "data_stream_a12", "data_stream_a21", "data_stream_a22", "data_stream_b1", "data_stream_b2")
                    .build()
                    .getIndicesLookup();

            static IndexResolverReplacer.Resolved resolved(String... indices) {
                ImmutableSet.Builder<String> allIndices = ImmutableSet.builder();

                for (String index : indices) {
                    IndexAbstraction indexAbstraction = INDEX_METADATA.get(index);

                    if (indexAbstraction instanceof IndexAbstraction.DataStream) {
                        allIndices.addAll(
                            indexAbstraction.getIndices().stream().map(i -> i.getIndex().getName()).collect(Collectors.toList())
                        );
                    }

                    allIndices.add(index);
                }

                return new IndexResolverReplacer.Resolved(
                    ImmutableSet.of(),
                    allIndices.build(),
                    ImmutableSet.copyOf(indices),
                    ImmutableSet.of(),
                    IndicesOptions.LENIENT_EXPAND_OPEN
                );
            }
        }

        static class IndexSpec {
            ImmutableList<String> givenIndexPrivs = ImmutableList.of();
            boolean wildcardPrivs;
            Map<String, IndexAbstraction> indexMetadata;

            IndexSpec() {}

            IndexSpec givenIndexPrivs(String... indexPatterns) {
                this.givenIndexPrivs = ImmutableList.copyOf(indexPatterns);
                this.wildcardPrivs = this.givenIndexPrivs.contains("*");
                return this;
            }

            boolean covers(User user, String index) {
                if (this.wildcardPrivs) {
                    return true;
                }

                for (String givenIndexPriv : this.givenIndexPrivs) {
                    if (givenIndexPriv.contains("${")) {
                        for (Map.Entry<String, String> entry : user.getCustomAttributesMap().entrySet()) {
                            givenIndexPriv = givenIndexPriv.replace("${" + entry.getKey() + "}", entry.getValue());
                        }
                    }

                    if (givenIndexPriv.endsWith("*")) {
                        if (index.startsWith(givenIndexPriv.substring(0, givenIndexPriv.length() - 1))) {
                            return true;
                        }

                        for (IndexAbstraction indexAbstraction : indexMetadata.values()) {
                            if ((indexAbstraction instanceof IndexAbstraction.Alias
                                || indexAbstraction instanceof IndexAbstraction.DataStream)
                                && indexAbstraction.getName().startsWith(givenIndexPriv.substring(0, givenIndexPriv.length() - 1))) {
                                if (indexAbstraction.getIndices().stream().anyMatch(i -> i.getIndex().getName().equals(index))) {
                                    return true;
                                }
                            }
                        }
                    } else if (givenIndexPrivs.contains("*")) {
                        // For simplicity, we only allow a sub-set of patterns. We assume here that the WildcardMatcher
                        // class fulfills all other cases correctly as per its contract
                        throw new RuntimeException("The tests only support index patterns with * at the end");
                    } else {
                        if (index.equals(givenIndexPriv)) {
                            return true;
                        }

                        IndexAbstraction indexAbstraction = indexMetadata.get(index);

                        if (indexAbstraction instanceof IndexAbstraction.Alias || indexAbstraction instanceof IndexAbstraction.DataStream) {
                            if (indexAbstraction.getIndices().stream().anyMatch(i -> i.getIndex().getName().equals(index))) {
                                return true;
                            }
                        }
                    }
                }

                return false;
            }

            SecurityDynamicConfiguration<RoleV7> toRolesConfig(ActionSpec actionSpec) {
                try {
                    return SecurityDynamicConfiguration.fromMap(
                        ImmutableMap.of(
                            "test_role",
                            ImmutableMap.of(
                                "index_permissions",
                                Arrays.asList(
                                    ImmutableMap.of("index_patterns", this.givenIndexPrivs, "allowed_actions", actionSpec.givenPrivs)
                                )
                            )
                        ),
                        CType.ROLES
                    );
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public String toString() {
                return this.givenIndexPrivs.stream().collect(Collectors.joining(","));
            }
        }

        static class ActionSpec {
            String name;
            ImmutableList<String> givenPrivs;
            ImmutableSet<String> requiredPrivs;
            String primaryAction;
            boolean wellKnownActions;

            ActionSpec(String name) {
                super();
                this.name = name;
            }

            ActionSpec givenPrivs(String... actions) {
                this.givenPrivs = ImmutableList.copyOf(actions);
                return this;
            }

            ActionSpec requiredPrivs(String... requiredPrivs) {
                this.requiredPrivs = ImmutableSet.copyOf(requiredPrivs);
                this.primaryAction = requiredPrivs[0];
                this.wellKnownActions = this.requiredPrivs.stream().anyMatch(a -> WellKnownActions.INDEX_ACTIONS.contains(a));
                return this;
            }

            @Override
            public String toString() {
                return name;
            }
        }

        enum Statefulness {
            STATEFUL,
            STATEFUL_LIMITED,
            NON_STATEFUL
        }
    }

    public static class Misc {
        @Test
        public void relevantOnly_identity() throws Exception {
            Map<String, IndexAbstraction> metadata = //
                indices("index_a11", "index_a12", "index_b")//
                    .alias("alias_a")
                    .of("index_a11", "index_a12")//
                    .build()
                    .getIndicesLookup();

            assertTrue(
                "relevantOnly() returned identical object",
                ActionPrivileges.StatefulIndexPrivileges.relevantOnly(metadata) == metadata
            );
        }

        @Test
        public void relevantOnly_closed() throws Exception {
            Map<String, IndexAbstraction> metadata = indices("index_open_1", "index_open_2")//
                .index("index_closed", IndexMetadata.State.CLOSE)
                .build()
                .getIndicesLookup();

            assertNotNull("Original metadata contains index_open_1", metadata.get("index_open_1"));
            assertNotNull("Original metadata contains index_closed", metadata.get("index_closed"));

            Map<String, IndexAbstraction> filteredMetadata = ActionPrivileges.StatefulIndexPrivileges.relevantOnly(metadata);

            assertNotNull("Filtered metadata contains index_open_1", filteredMetadata.get("index_open_1"));
            assertNull("Filtered metadata does not contain index_closed", filteredMetadata.get("index_closed"));
        }

        @Test
        public void relevantOnly_dataStreamBackingIndices() throws Exception {
            Map<String, IndexAbstraction> metadata = dataStreams("data_stream_1").build().getIndicesLookup();

            assertNotNull("Original metadata contains backing index", metadata.get(".ds-data_stream_1-000001"));
            assertNotNull("Original metadata contains data stream", metadata.get("data_stream_1"));

            Map<String, IndexAbstraction> filteredMetadata = ActionPrivileges.StatefulIndexPrivileges.relevantOnly(metadata);

            assertNull("Filtered metadata does not contain backing index", filteredMetadata.get(".ds-data_stream_1-000001"));
            assertNotNull("Filtered metadata contains data stream", filteredMetadata.get("data_stream_1"));
        }

        @Test
        public void backingIndexToDataStream() {
            Map<String, IndexAbstraction> metadata = indices("index").dataStream("data_stream").build().getIndicesLookup();

            assertEquals("index", ActionPrivileges.StatefulIndexPrivileges.backingIndexToDataStream("index", metadata));
            assertEquals(
                "data_stream",
                ActionPrivileges.StatefulIndexPrivileges.backingIndexToDataStream(".ds-data_stream-000001", metadata)
            );
            assertEquals("non_existing", ActionPrivileges.StatefulIndexPrivileges.backingIndexToDataStream("non_existing", metadata));
        }

        @Test
        public void hasIndexPrivilege_errors() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
                "role_with_errors:\n"
                    + "  index_permissions:\n"
                    + "  - index_patterns: ['/invalid_regex_with_attr${user.name}\\/']\n"
                    + "    allowed_actions: ['indices:some_action*', 'indices:data/write/index']",
                CType.ROLES
            );

            ActionPrivileges subject = new ActionPrivileges(
                roles,
                FlattenedActionGroups.EMPTY,
                () -> Collections.emptyMap(),
                Settings.EMPTY
            );

            PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(
                ctx("role_with_errors"),
                Set.of("indices:some_action", "indices:data/write/index"),
                IndexResolverReplacer.Resolved.ofIndex("any_index")
            );
            assertThat(result, isForbidden());
            assertTrue(result.hasEvaluationExceptions());
            assertTrue(
                "Result mentions role_with_errors: " + result.getEvaluationExceptionInfo(),
                result.getEvaluationExceptionInfo()
                    .startsWith("Exceptions encountered during privilege evaluation:\n" + "Error while evaluating role role_with_errors")
            );
        }

        @Test
        public void hasExplicitIndexPrivilege_errors() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
                "role_with_errors:\n"
                    + "  index_permissions:\n"
                    + "  - index_patterns: ['/invalid_regex_with_attr${user.name}\\/']\n"
                    + "    allowed_actions: ['system:admin/system_index*']",
                CType.ROLES
            );

            ActionPrivileges subject = new ActionPrivileges(
                roles,
                FlattenedActionGroups.EMPTY,
                () -> Collections.emptyMap(),
                Settings.EMPTY
            );

            PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(
                ctx("role_with_errors"),
                Set.of("system:admin/system_index"),
                IndexResolverReplacer.Resolved.ofIndex("any_index")
            );
            assertThat(result, isForbidden());
            assertTrue(result.hasEvaluationExceptions());
            assertTrue(
                "Result mentions role_with_errors: " + result.getEvaluationExceptionInfo(),
                result.getEvaluationExceptionInfo()
                    .startsWith("Exceptions encountered during privilege evaluation:\n" + "Error while evaluating role role_with_errors")
            );
        }
    }

    /**
     * Verifies that the heap size used by StatefulIndexPrivileges stays within expected bounds.
     */
    @RunWith(Parameterized.class)
    public static class StatefulIndexPrivilegesHeapSize {

        final Map<String, IndexAbstraction> indices;
        final SecurityDynamicConfiguration<RoleV7> roles;
        final int expectedEstimatedNumberOfBytes;

        @Test
        public void estimatedSize() throws Exception {
            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, () -> indices, Settings.EMPTY);

            subject.updateStatefulIndexPrivileges(indices, 1);

            int lowerBound = (int) (expectedEstimatedNumberOfBytes * 0.9);
            int upperBound = (int) (expectedEstimatedNumberOfBytes * 1.1);

            int actualEstimatedNumberOfBytes = subject.getEstimatedStatefulIndexByteSize();

            assertTrue(
                "estimatedNumberOfBytes: " + lowerBound + " < " + actualEstimatedNumberOfBytes + " < " + upperBound,
                lowerBound < actualEstimatedNumberOfBytes && actualEstimatedNumberOfBytes < upperBound
            );
        }

        public StatefulIndexPrivilegesHeapSize(int numberOfIndices, int numberOfRoles, int expectedEstimatedNumberOfBytes) {
            this.indices = createIndices(numberOfIndices);
            this.roles = createRoles(numberOfRoles, numberOfIndices);
            this.expectedEstimatedNumberOfBytes = expectedEstimatedNumberOfBytes;
        }

        @Parameterized.Parameters(name = "{0} indices; {1} roles; estimated number of bytes: {2}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            // indices; roles; expected number of bytes
            result.add(new Object[] { 100, 10, 10_000 });
            result.add(new Object[] { 100, 100, 13_000 });
            result.add(new Object[] { 100, 1000, 26_000 });

            result.add(new Object[] { 1000, 10, 92_000 });
            result.add(new Object[] { 1000, 100, 94_000 });
            result.add(new Object[] { 1000, 1000, 112_000 });

            result.add(new Object[] { 10_000, 10, 890_000 });
            result.add(new Object[] { 10_000, 100, 930_000 });

            return result;
        }

        static Map<String, IndexAbstraction> createIndices(int numberOfIndices) {
            String[] names = new String[numberOfIndices];

            for (int i = 0; i < numberOfIndices; i++) {
                names[i] = "index_" + i;
            }

            return MockIndexMetadataBuilder.indices(names).build().getIndicesLookup();
        }

        static SecurityDynamicConfiguration<RoleV7> createRoles(int numberOfRoles, int numberOfIndices) {
            try {
                Random random = new Random(1);
                Map<String, Object> rolesDocument = new HashMap<>();
                List<String> allowedActions = Arrays.asList(
                    "indices:data/read*",
                    "indices:admin/mappings/fields/get*",
                    "indices:admin/resolve/index",
                    "indices:data/write*",
                    "indices:admin/mapping/put"
                );

                for (int i = 0; i < numberOfRoles; i++) {
                    List<String> indexPatterns = new ArrayList<>();
                    int numberOfIndexPatterns = Math.min(
                        (int) ((Math.abs(random.nextGaussian() + 0.3)) * 0.5 * numberOfIndices),
                        numberOfIndices
                    );

                    int numberOfIndexPatterns10th = numberOfIndexPatterns / 10;

                    if (numberOfIndexPatterns10th > 0) {
                        for (int k = 0; k < numberOfIndexPatterns10th; k++) {
                            indexPatterns.add("index_" + random.nextInt(numberOfIndices / 10) + "*");
                        }
                    } else {
                        for (int k = 0; k < numberOfIndexPatterns; k++) {
                            indexPatterns.add("index_" + random.nextInt(numberOfIndices));
                        }
                    }

                    Map<String, Object> roleDocument = ImmutableMap.of(
                        "index_permissions",
                        Arrays.asList(ImmutableMap.of("index_patterns", indexPatterns, "allowed_actions", allowedActions))
                    );

                    rolesDocument.put("role_" + i, roleDocument);
                }

                return SecurityDynamicConfiguration.fromMap(rolesDocument, CType.ROLES);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    static PrivilegesEvaluationContext ctx(String... roles) {
        User user = new User("test_user");
        user.addAttributes(ImmutableMap.of("attrs.dept_no", "a11"));
        return new PrivilegesEvaluationContext(
            user,
            ImmutableSet.copyOf(roles),
            null,
            null,
            null,
            null,
            new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)),
            null
        );
    }
}
