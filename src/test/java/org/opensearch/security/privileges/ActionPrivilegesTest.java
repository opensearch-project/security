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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.Assert.assertThat;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isAllowed;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isForbidden;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isPartiallyOk;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.missingPrivileges;
import static org.opensearch.security.util.MockIndexMetadataBuilder.dataStreams;
import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;

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
    ActionPrivilegesTest.IndexPrivileges.DataStreams.class })
public class ActionPrivilegesTest {
    public static class ClusterPrivileges {
        @Test
        public void clusterAction_wellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
                //
                "test_role:\n" + //
                    "  cluster_permissions:\n" + //
                    "  - cluster:monitor/nodes/stats*",
                CType.ROLES
            );

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null);

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
        public void clusterAction_notWellKnown() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
                //
                "test_role:\n" + //
                    "  cluster_permissions:\n" + //
                    "  - cluster:monitor/nodes/stats*",
                CType.ROLES
            );

            ActionPrivileges subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, null);

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
    }

    /**
     * Tests for index privileges. This class contains two parameterized test suites, first for indices and aliases,
     * second for data streams.
     *
     * Both test suites use parameters to create a 3-dimensional test case space to make sure all code paths are covered.
     *
     * The dimensions are (see also the params() methods):
     *
     * 1. roles.yml; index patterns: Different usages of patterns, wildcards and constant names.
     * 2. roles.yml; action patterns: Well known actions vs non-well known actions combined with use of patterns vs use of constant action names
     * 3. Statefulness: Shall the data structures from ActionPrivileges.StatefulIndexPrivileges be used or not
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
            public void negative_wrongRole() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("other_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, requiredActions, resolved("index_a11"));
                assertThat(result, isForbidden(missingPrivileges(requiredActions)));
            }

            @Test
            public void negative_wrongAction() throws Exception {
                PrivilegesEvaluationContext ctx = ctx("test_role");
                PrivilegesEvaluatorResponse result = subject.hasIndexPrivilege(ctx, otherActions, resolved("index_a11"));
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
                    //
                    new IndexSpec().givenIndexPrivs("*"), //
                    new IndexSpec().givenIndexPrivs("index_*"), //
                    new IndexSpec().givenIndexPrivs("index_a11"), //
                    new IndexSpec().givenIndexPrivs("index_a1*"), //
                    new IndexSpec().givenIndexPrivs("index_${attrs.dept_no}"), //
                    new IndexSpec().givenIndexPrivs("alias_a1*") //
                )) {
                    for (ActionSpec actionSpec : Arrays.asList(
                        //
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

                this.subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, () -> INDEX_METADATA);

                if (statefulness == Statefulness.STATEFUL) {
                    this.subject.updateStatefulIndexPrivileges(INDEX_METADATA);
                }
            }

            final static ImmutableMap<String, IndexAbstraction> INDEX_METADATA = //
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

            static IndexResolverReplacer.Resolved resolved(String... indices) {
                return new IndexResolverReplacer.Resolved(
                    ImmutableSet.of(),
                    ImmutableSet.copyOf(indices),
                    ImmutableSet.of(),
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
                    //
                    new IndexSpec().givenIndexPrivs("*"), //
                    new IndexSpec().givenIndexPrivs("data_stream_*"), //
                    new IndexSpec().givenIndexPrivs("data_stream_a11"), //
                    new IndexSpec().givenIndexPrivs("data_stream_a1*"), //
                    new IndexSpec().givenIndexPrivs("data_stream_${attrs.dept_no}"), //
                    new IndexSpec().givenIndexPrivs(".ds-data_stream_a11*") //
                )) {
                    for (ActionSpec actionSpec : Arrays.asList(
                        //
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

                this.subject = new ActionPrivileges(roles, FlattenedActionGroups.EMPTY, () -> INDEX_METADATA);

                if (statefulness == Statefulness.STATEFUL) {
                    this.subject.updateStatefulIndexPrivileges(INDEX_METADATA);
                }
            }

            final static ImmutableMap<String, IndexAbstraction> INDEX_METADATA = //
                dataStreams("data_stream_a11", "data_stream_a12", "data_stream_a21", "data_stream_a22", "data_stream_b1", "data_stream_b2")
                    .build();

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
                    ImmutableSet.of(),
                    ImmutableSet.of(),
                    IndicesOptions.LENIENT_EXPAND_OPEN
                );
            }

        }

        static class IndexSpec {
            ImmutableList<String> givenIndexPrivs = ImmutableList.of();
            boolean wildcardPrivs;
            ImmutableMap<String, IndexAbstraction> indexMetadata;

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
                            "test_role", //
                            ImmutableMap.of(
                                //
                                "index_permissions",
                                Arrays.asList(
                                    //
                                    ImmutableMap.of("index_patterns", this.givenIndexPrivs, "allowed_actions", actionSpec.givenPrivs)
                                )//
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
            NON_STATEFUL
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
            new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY))
        );
    }
}
