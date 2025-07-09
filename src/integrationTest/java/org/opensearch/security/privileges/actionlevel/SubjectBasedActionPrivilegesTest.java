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
package org.opensearch.security.privileges.actionlevel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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

import org.opensearch.action.OriginalIndices;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isAllowed;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isForbidden;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isPartiallyOk;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.missingPrivileges;
import static org.opensearch.security.util.MockIndexMetadataBuilder.dataStreams;
import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.opensearch.security.util.MockPrivilegeEvaluationContextBuilder.ctx;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for SubjectBasedActionPrivilegesTest. As the ActionPrivileges provides quite a few different code paths for checking
 * privileges with different performance characteristics, this test suite defines different test cases for making sure
 * all these code paths are tested. So, all functionality must be tested for "well-known" actions and non-well-known
 * actions. For index privileges, there are a couple of more tests dimensions. See below.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    SubjectBasedActionPrivilegesTest.ClusterPrivileges.class,
    SubjectBasedActionPrivilegesTest.IndexPrivileges.IndicesAndAliases.class,
    SubjectBasedActionPrivilegesTest.IndexPrivileges.DataStreams.class,
    SubjectBasedActionPrivilegesTest.Misc.class })
public class SubjectBasedActionPrivilegesTest {
    public static class ClusterPrivileges {
        @Test
        public void wellKnown() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - cluster:monitor/nodes/stats*
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasClusterPrivilege(ctx().get(), "cluster:monitor/nodes/stats"), isAllowed());
        }

        @Test
        public void notWellKnown() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - cluster:monitor/nodes/stats*
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasClusterPrivilege(ctx().get(), "cluster:monitor/nodes/stats/somethingnotwellknown"), isAllowed());
        }

        @Test
        public void negative() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - cluster:monitor/nodes/stats*
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasClusterPrivilege(ctx().get(), "cluster:monitor/nodes/foo"), isForbidden());
        }

        @Test
        public void wildcard() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - '*'
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasClusterPrivilege(ctx().get(), "cluster:whatever"), isAllowed());
        }

        @Test
        public void explicit_wellKnown() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - cluster:monitor/nodes/stats
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasExplicitClusterPrivilege(ctx().get(), "cluster:monitor/nodes/stats"), isAllowed());
        }

        @Test
        public void explicit_notWellKnown() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - cluster:monitor/nodes/*
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasExplicitClusterPrivilege(ctx().get(), "cluster:monitor/nodes/notwellknown"), isAllowed());
        }

        @Test
        public void explicit_notExplicit() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - '*'
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(
                subject.hasExplicitClusterPrivilege(ctx().get(), "cluster:monitor/nodes/stats"),
                isForbidden(missingPrivileges("cluster:monitor/nodes/stats"))
            );
        }

        @Test
        public void hasAny_wellKnown() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - cluster:monitor/nodes/stats*
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasAnyClusterPrivilege(ctx().get(), ImmutableSet.of("cluster:monitor/nodes/stats")), isAllowed());
        }

        @Test
        public void hasAny_wildcard() throws Exception {
            RoleV7 config = config("""
                cluster_permissions:
                - '*'
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );
            assertThat(subject.hasAnyClusterPrivilege(ctx().get(), ImmutableSet.of("cluster:monitor/nodes/stats")), isAllowed());
        }
    }

    public static class IndexPrivileges {

        @RunWith(Parameterized.class)
        public static class IndicesAndAliases {
            final ActionSpec actionSpec;
            final IndexSpec indexSpec;
            final RoleV7 config;
            final String primaryAction;
            final ImmutableSet<String> requiredActions;
            final ImmutableSet<String> otherActions;
            final SubjectBasedActionPrivileges subject;

            @Test
            public void positive_full() throws Exception {
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(
                    ctx().attr("attrs.dept_no", "a11").indexMetadata(INDEX_METADATA).get(),
                    requiredActions,
                    resolved("index_a11")
                );
                assertThat(result, isAllowed());
            }

            @Test
            public void positive_partial() throws Exception {
                PrivilegesEvaluationContext ctx = ctx().indexMetadata(INDEX_METADATA).get();
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
                PrivilegesEvaluationContext ctx = ctx().indexMetadata(INDEX_METADATA).get();
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
                ResolvedIndices resolved = ResolvedIndices.of(Collections.emptySet())
                    .withRemoteIndices(
                        Map.of(
                            "remote",
                            new OriginalIndices(new String[] { "a" }, IndicesOptions.STRICT_SINGLE_INDEX_NO_EXPAND_FORBID_CLOSED)
                        )
                    );
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(
                    ctx().indexMetadata(INDEX_METADATA).get(),
                    requiredActions,
                    resolved
                );
                assertThat(result, isAllowed());
            }

            @Test
            public void negative_wrongAction() throws Exception {
                PrivilegesEvaluationContext ctx = ctx().attr("attrs.dept_no", "a11").indexMetadata(INDEX_METADATA).get();
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, otherActions, resolved("index_a11"));

                if (actionSpec.givenPrivs.contains("*")) {
                    assertThat(result, isAllowed());
                } else {
                    assertThat(result, isForbidden(missingPrivileges(otherActions)));
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

            @Parameterized.Parameters(name = "{0};  actions: {1}")
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
                        result.add(new Object[] { indexSpec, actionSpec });
                    }
                }
                return result;
            }

            public IndicesAndAliases(IndexSpec indexSpec, ActionSpec actionSpec) throws Exception {
                this.indexSpec = indexSpec;
                this.actionSpec = actionSpec;
                this.config = indexSpec.toConfig(actionSpec);

                this.primaryAction = actionSpec.primaryAction;
                this.requiredActions = actionSpec.requiredPrivs;

                this.otherActions = actionSpec.wellKnownActions
                    ? ImmutableSet.of("indices:data/write/update")
                    : ImmutableSet.of("indices:foobar/unknown");
                this.indexSpec.indexMetadata = INDEX_METADATA.getIndicesLookup();

                this.subject = new SubjectBasedActionPrivileges(
                    config,
                    FlattenedActionGroups.EMPTY,
                    RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
                );
            }

            final static Metadata INDEX_METADATA = //
                indices("index_a11", "index_a12", "index_a21", "index_a22", "index_b1", "index_b2")//
                    .alias("alias_a")
                    .of("index_a11", "index_a12", "index_a21", "index_a22")//
                    .alias("alias_a1")
                    .of("index_a11", "index_a12")//
                    .alias("alias_a2")
                    .of("index_a21", "index_a22")//
                    .alias("alias_b")
                    .of("index_b1", "index_b2")//
                    .build();

            static ResolvedIndices resolved(String... indices) {
                return ResolvedIndices.of(indices);
            }

        }

        @RunWith(Parameterized.class)
        public static class DataStreams {
            final ActionSpec actionSpec;
            final IndexSpec indexSpec;
            final RoleV7 config;
            final String primaryAction;
            final ImmutableSet<String> requiredActions;
            final ImmutableSet<String> otherActions;
            final SubjectBasedActionPrivileges subject;

            @Test
            public void positive_full() throws Exception {
                PrivilegesEvaluationContext ctx = ctx().indexMetadata(INDEX_METADATA).get();
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
                PrivilegesEvaluationContext ctx = ctx().indexMetadata(INDEX_METADATA).get();
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
            public void negative_wrongAction() throws Exception {
                PrivilegesEvaluationContext ctx = ctx().indexMetadata(INDEX_METADATA).get();
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

            @Parameterized.Parameters(name = "{0};  actions: {1}")
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
                        result.add(new Object[] { indexSpec, actionSpec });
                    }
                }
                return result;
            }

            public DataStreams(IndexSpec indexSpec, ActionSpec actionSpec) throws Exception {
                this.indexSpec = indexSpec;
                this.actionSpec = actionSpec;
                this.config = indexSpec.toConfig(actionSpec);

                this.primaryAction = actionSpec.primaryAction;
                this.requiredActions = actionSpec.requiredPrivs;

                this.otherActions = actionSpec.wellKnownActions
                    ? ImmutableSet.of("indices:data/write/update")
                    : ImmutableSet.of("indices:foobar/unknown");
                this.indexSpec.indexMetadata = INDEX_METADATA.getIndicesLookup();
                this.subject = new SubjectBasedActionPrivileges(
                    config,
                    FlattenedActionGroups.EMPTY,
                    RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
                );
            }

            final static Metadata INDEX_METADATA = //
                dataStreams("data_stream_a11", "data_stream_a12", "data_stream_a21", "data_stream_a22", "data_stream_b1", "data_stream_b2")
                    .build();

            static ResolvedIndices resolved(String... indices) {
                return ResolvedIndices.of(indices);
                /* TODO CHECK
                ImmutableSet.Builder<String> allIndices = ImmutableSet.builder();

                for (String index : indices) {
                    IndexAbstraction indexAbstraction = INDEX_METADATA.getIndicesLookup().get(index);

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

                 */
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

            RoleV7 toConfig(ActionSpec actionSpec) {
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
                    ).getCEntry("test_role");
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
    }

    public static class Misc {

        @Test
        public void hasExplicitIndexPrivilege_positive() throws Exception {
            RoleV7 config = config("""
                index_permissions:
                - index_patterns: ['test_index']
                  allowed_actions: ['system:admin/system_index']
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );

            PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(
                ctx().get(),
                Set.of("system:admin/system_index"),
                ResolvedIndices.of("test_index")
            );
            assertThat(result, isAllowed());
        }

        @Test
        public void hasExplicitIndexPrivilege_positive_pattern() throws Exception {
            RoleV7 config = config("""
                index_permissions:
                - index_patterns: ['test_index']
                  allowed_actions: ['system:admin/system_index*']
                """);

            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );

            PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(
                ctx().get(),
                Set.of("system:admin/system_index"),
                ResolvedIndices.of("test_index")
            );
            assertThat(result, isAllowed());
        }

        @Test
        public void hasExplicitIndexPrivilege_noWildcard() throws Exception {
            RoleV7 config = config("""
                index_permissions:
                - index_patterns: ['test_index']
                  allowed_actions: ['*']
                """);
            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );

            PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(
                ctx().get(),
                Set.of("system:admin/system_index"),
                ResolvedIndices.of("test_index")
            );
            assertThat(result, isForbidden());
        }

        @Test
        public void hasExplicitIndexPrivilege_negative_wrongAction() throws Exception {
            RoleV7 config = config("""
                index_permissions:
                - index_patterns: ['test_index']
                  allowed_actions: ['system:admin/system*']
                """);
            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );

            PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(
                ctx().get(),
                Set.of("system:admin/system_foo"),
                ResolvedIndices.of("test_index")
            );
            assertThat(result, isForbidden());
        }

        @Test
        public void hasExplicitIndexPrivilege_errors() throws Exception {
            RoleV7 config = config("""
                index_permissions:
                - index_patterns: ['/invalid_regex${user.name}\\/']
                  allowed_actions: ['system:admin/system*']
                """);
            SubjectBasedActionPrivileges subject = new SubjectBasedActionPrivileges(
                config,
                FlattenedActionGroups.EMPTY,
                RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE
            );

            PrivilegesEvaluatorResponse result = subject.hasExplicitIndexPrivilege(
                ctx().get(),
                Set.of("system:admin/system_index"),
                ResolvedIndices.of("test_index")
            );
            assertThat(result, isForbidden());
            assertTrue(result.hasEvaluationExceptions());
            assertTrue(
                "Result contains exception info: " + result.getEvaluationExceptionInfo(),
                result.getEvaluationExceptionInfo().startsWith("Exceptions encountered during privilege evaluation:")
            );
        }

    }

    static RoleV7 config(String config) {
        return RoleV7.fromYamlStringUnchecked(config);
    }
}
