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
package org.opensearch.security.privileges.dlsfls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;
import org.hamcrest.Matcher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;

import org.opensearch.action.IndicesRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.CheckedFunction;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.ParseField;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BaseTermQueryBuilder;
import org.opensearch.index.query.MatchNoneQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.test.framework.TestSecurityConfig;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.util.MockIndexMetadataBuilder.dataStreams;
import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for the DocumentPrivileges class and the underlying AbstractRuleBasedPrivileges class. As these classes
 * provide a number of different code paths for checking privileges, the inner test classes use parameterized tests
 * to define test matrices to make sure all the code paths are covered. The dimensions of the matrices are:
 * <ul>
 *     <li>Different user configurations: With user attrs, without user attrs, with single role, with mixed roles
 *     <li>Statefulness: As the AbstractRuleBasedPrivileges.StatefulRules class can either cover certain indices or not,
 *     this parameter simulates whether an index is covered or not. This is because the AbstractRuleBasedPrivileges.StatefulRules class
 *     is updated asynchronously and thus might just cover an index later.
 *     <li>DfmEmptyOverridesAll: The state of the "plugins.security.dfm_empty_overrides_all" setting.
 * </ul>
 * Note: The individual check these parameters and choose the correct assertions based on these parameters.
 * This creates quite complex conditions, which might take a while to get an overview over - I am not too happy
 * about this. The alternative would be a test oracle, which however will much more complex.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    DocumentPrivilegesTest.IndicesAndAliases_getRestriction.class,
    DocumentPrivilegesTest.IndicesAndAliases_isUnrestricted.class,
    DocumentPrivilegesTest.DataStreams_getRestriction.class,
    DocumentPrivilegesTest.DlsQuery.class })
public class DocumentPrivilegesTest {

    static NamedXContentRegistry xContentRegistry = new NamedXContentRegistry(
        ImmutableList.of(
            new NamedXContentRegistry.Entry(
                QueryBuilder.class,
                new ParseField(TermQueryBuilder.NAME),
                (CheckedFunction<XContentParser, TermQueryBuilder, IOException>) (p) -> TermQueryBuilder.fromXContent(p)
            )
        )
    );

    @RunWith(Parameterized.class)
    public static class IndicesAndAliases_getRestriction {
        final static Metadata INDEX_METADATA = //
            indices("index_a1", "index_a2", "index_b1", "index_b2")//
                .alias("alias_a")
                .of("index_a1", "index_a2")//
                .build();

        final static ClusterState CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(INDEX_METADATA).build();

        final static IndexAbstraction.Index index_a1 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_a1");
        final static IndexAbstraction.Index index_a2 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_a2");
        final static IndexAbstraction.Index index_b1 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_b1");

        final Statefulness statefulness;
        final UserSpec userSpec;
        final User user;
        final IndexSpec indexSpec;
        final IndexAbstraction.Index index;
        final PrivilegesEvaluationContext context;
        final boolean dfmEmptyOverridesAll;

        @Test
        public void wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*")
            );
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role") && dfmEmptyOverridesAll) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                // If we have two DLS roles, we get the union of queries as restriction
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
            } else if (userSpec.roles.contains("dls_role_1")) {
                // Only one role: Check that the restriction matches the role definition above.
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
            } else if (userSpec.roles.contains("dls_role_2")) {
                // Only one role: Check that the restriction matches the role definition above.
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
            } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                // If dfmEmptyOverridesAll == false, roles with restrictions take precedence over roles without restrictions
                // Thus, this check comes after the checks for the cases with present DLS roles
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                // Users without any roles do not have any privileges to access anything
                assertThat(dlsRestriction, isFullyRestricted());
            } else {
                fail("Missing case for " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }

            IndexToRuleMap<DlsRestriction> restrictionMap = subject.getRestrictions(context, Collections.singleton(index.getName()));
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("restrictionMap should be unrestricted according to " + dlsRestriction, restrictionMap.isUnrestricted());
            } else {
                assertEquals(
                    "restrictiobMap should contain " + dlsRestriction,
                    dlsRestriction.getQueries(),
                    restrictionMap.getIndexMap().get(index.getName()).getQueries()
                );
            }
        }

        @Test
        public void indexPattern() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("index_a*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_b*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*")
            );
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role") && dfmEmptyOverridesAll) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.contains("dls_role_1") || userSpec.roles.contains("dls_role_2")) {
                // As the roles use index patterns, we have to check the requested index in order to know the effective restrictions
                if (index == index_a1 || index == index_a2) {
                    // Only dls_role_1 and non_dls_role match index_a1 or index_a2. We need to check the effective roles.
                    if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                } else if (index == index_b1) {
                    // Only dls_role_2 and non_dls_role match index_b1. We need to check the effective roles.
                    if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                }
            } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                // If dfmEmptyOverridesAll == false, roles with restrictions take precedence over roles without restrictions
                // Thus, this check comes after the checks for the cases with present DLS roles
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                // Users without any roles do not have any privileges to access anything
                assertThat(dlsRestriction, isFullyRestricted());
            } else {
                fail("Missing case for " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Test
        public void indexPatternTemplate() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("index_${attr.attr_a}1"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_${attr.attr_a}*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("index_${attr.attr_a}*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (index == index_b1) {
                // This test case never grants privileges to index_b1
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.attributes.isEmpty()) {
                // As all the roles in our roleConfig (see above) use user attributes, these won't work with
                // users without attributes. Then, access should be also restricted
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.roles.contains("non_dls_role") && dfmEmptyOverridesAll) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.contains("dls_role_1") || userSpec.roles.contains("dls_role_2")) {
                // As the roles use index patterns, we have to check the requested index in order to know the effective restrictions
                if (index == index_a1) {
                    // dls_role_1, dls_role_2 and non_dls_role match index_a1.
                    if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else {
                        assertThat(dlsRestriction, isUnrestricted());
                    }
                } else if (index == index_a2) {
                    // only dls_role_2 and non_dls_role match index_a2
                    if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                }
            } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                // Users without any roles do not have any privileges to access anything
                assertThat(dlsRestriction, isFullyRestricted());
            } else {
                fail("Missing case for " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Test
        public void queryPatternTemplate() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls("{\"term\": {\"dept\": \"${attr.attr_a}1\"}}")
                    .on("index_a1"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls("{\"term\": {\"dept\": \"${attr.attr_a}2\"}}")
                    .on("index_a*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("index_a*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (index == index_b1) {
                // This test case never grants privileges to index_b1
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.attributes.isEmpty()) {
                // If a role uses undefined user attributes for DLS queries, the attribute templates
                // remain unchanged in the resulting query. This is a property of the current attribute handling code.
                // It would be probably better if an error would be raised in that case.
                if (index == index_a1) {
                    if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                        assertThat(
                            dlsRestriction,
                            isRestricted(termQuery("dept", "${attr.attr_a}1"), termQuery("dept", "${attr.attr_a}2"))
                        );
                    }
                }
            } else if (userSpec.roles.contains("non_dls_role") && dfmEmptyOverridesAll) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.contains("dls_role_1") || userSpec.roles.contains("dls_role_2")) {
                // As the roles use index patterns, we have to check the requested index in order to know the effective restrictions
                if (index == index_a1) {
                    // dls_role_1, dls_role_2 and non_dls_role match index_a1.
                    if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "a1"), termQuery("dept", "a2")));
                    } else if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "a1")));
                    } else {
                        assertThat(dlsRestriction, isUnrestricted());
                    }
                } else if (index == index_a2) {
                    // only dls_role_2 and non_dls_role match index_a2
                    if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "a2")));
                    } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                }
            } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                // Users without any roles do not have any privileges to access anything
                assertThat(dlsRestriction, isFullyRestricted());
            } else {
                fail("Missing case for " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Test
        public void alias() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("alias_a"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_a2"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("alias_a")
            );
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.isEmpty()) {
                // Users without any roles do not have any privileges to access anything
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == index_a1) {
                if (userSpec.roles.contains("non_dls_role") && dfmEmptyOverridesAll) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == index_a2) {
                if (userSpec.roles.contains("non_dls_role") && dfmEmptyOverridesAll) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                } else if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else if (userSpec.roles.contains("non_dls_role") && !dfmEmptyOverridesAll) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == index_b1) {
                // index_b1 is not member of alias_a. Thus, the role defintion does not give any privileges.
                assertThat(dlsRestriction, isFullyRestricted());
            } else {
                fail("Missing case for " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Parameterized.Parameters(name = "{0}; {1}; {2}; {3}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            for (UserSpec userSpec : Arrays.asList(
                new UserSpec("non_dls_role", "non_dls_role"), //
                new UserSpec("dls_role_1", "dls_role_1"), //
                new UserSpec("dls_role_1 and dls_role_2", "dls_role_1", "dls_role_2"), //
                new UserSpec("dls_role_1 and non_dls_role", "dls_role_1", "non_dls_role"), //
                new UserSpec("non_dls_role, attributes", "non_dls_role").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1, attributes", "dls_role_1").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1 and dls_role_2, attributes", "dls_role_1", "dls_role_2").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1 and non_dls_role, attributes", "dls_role_1", "non_dls_role").attribute("attr.attr_a", "a"), //
                new UserSpec("no roles")//
            )) {
                for (IndexSpec indexSpec : Arrays.asList(
                    new IndexSpec("index_a1"), //
                    new IndexSpec("index_a2"), //
                    new IndexSpec("index_b1")
                )) {
                    for (Statefulness statefulness : Statefulness.values()) {
                        for (DfmEmptyOverridesAll dfmEmptyOverridesAll : DfmEmptyOverridesAll.values()) {
                            result.add(new Object[] { userSpec, indexSpec, statefulness, dfmEmptyOverridesAll });
                        }
                    }
                }
            }
            return result;
        }

        public IndicesAndAliases_getRestriction(
            UserSpec userSpec,
            IndexSpec indexSpec,
            Statefulness statefulness,
            DfmEmptyOverridesAll dfmEmptyOverridesAll
        ) {
            this.userSpec = userSpec;
            this.indexSpec = indexSpec;
            this.user = userSpec.buildUser();
            this.index = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get(indexSpec.index);
            this.context = new PrivilegesEvaluationContext(
                this.user,
                ImmutableSet.copyOf(userSpec.roles),
                null,
                null,
                null,
                null,
                null,
                () -> CLUSTER_STATE
            );
            this.statefulness = statefulness;
            this.dfmEmptyOverridesAll = dfmEmptyOverridesAll == DfmEmptyOverridesAll.DFM_EMPTY_OVERRIDES_ALL_TRUE;
        }

        private DocumentPrivileges createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new DocumentPrivileges(
                roleConfig,
                statefulness == Statefulness.STATEFUL ? INDEX_METADATA.getIndicesLookup() : Map.of(),
                xContentRegistry,
                Settings.builder().put("plugins.security.dfm_empty_overrides_all", this.dfmEmptyOverridesAll).build()
            );
        }
    }

    @RunWith(Parameterized.class)
    public static class IndicesAndAliases_isUnrestricted {
        final static Metadata INDEX_METADATA = //
            indices("index_a1", "index_a2", "index_b1", "index_b2")//
                .alias("alias_a")
                .of("index_a1", "index_a2")//
                .build();

        final static ClusterState CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(INDEX_METADATA).build();

        final static IndexNameExpressionResolver INDEX_NAME_EXPRESSION_RESOLVER = new IndexNameExpressionResolver(
            new ThreadContext(Settings.EMPTY)
        );
        final static IndexResolverReplacer RESOLVER_REPLACER = new IndexResolverReplacer(
            INDEX_NAME_EXPRESSION_RESOLVER,
            () -> CLUSTER_STATE,
            null
        );

        final Statefulness statefulness;
        final UserSpec userSpec;
        final User user;
        final IndicesSpec indicesSpec;
        final IndexResolverReplacer.Resolved resolvedIndices;
        final PrivilegesEvaluationContext context;
        final boolean dfmEmptyOverridesAll;

        @Test
        public void wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            boolean result = subject.isUnrestricted(context, resolvedIndices);

            if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result.
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll && userSpec.roles.equals(ImmutableList.of("non_dls_role"))) {
                // For dfmEmptyOverridesAll == false, only non_dls_role must be there for an unrestricted result.
                assertTrue(result);
            } else {
                assertFalse(result);
            }
        }

        @Test
        public void indexPattern() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("index_a*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_b*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            boolean result = subject.isUnrestricted(context, resolvedIndices);

            if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll && userSpec.roles.equals(ImmutableList.of("non_dls_role"))) {
                // For dfmEmptyOverridesAll == false, only non_dls_role must be there for an unrestricted result.
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll
                && userSpec.roles.equals(ImmutableList.of("dls_role_1", "non_dls_role"))
                && indicesSpec.indices.equals(ImmutableList.of("index_b1"))) {
                    // index_b1 is only covered by non_dls_role, so we are also unrestricted here
                    assertTrue(result);
                } else {
                    assertFalse(result);
                }
        }

        @Test
        public void template() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("index_${attr.attr_a}1"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_${attr.attr_a}*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("index_${attr.attr_a}*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            boolean result = subject.isUnrestricted(context, resolvedIndices);

            if (indicesSpec.indices.contains("index_b1")) {
                // None of the roles above cover index_b1, so full restrictions should be assumed
                assertFalse(result);
            } else if (userSpec.attributes.isEmpty()) {
                // All roles defined above use attributes. If there are no user attributes, we must get a restricted result.
                assertFalse(result);
            } else if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result.
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll && userSpec.roles.equals(ImmutableList.of("non_dls_role"))) {
                // For dfmEmptyOverridesAll == false, only non_dls_role must be there for an unrestricted result.
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll
                && userSpec.roles.equals(ImmutableList.of("dls_role_1", "non_dls_role"))
                && indicesSpec.indices.equals(ImmutableList.of("index_a2"))) {
                    // index_a2 is not covered by this configuration
                    assertTrue(result);
                } else {
                    assertFalse(result);
                }
        }

        @Test
        public void alias_static() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("alias_a"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_a2"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("alias_a")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            boolean result = subject.isUnrestricted(context, resolvedIndices);

            if (resolvedIndices.getAllIndices().contains("index_b1")) {
                // index_b1 is not covered by any of the above roles, so there should be always a restriction
                assertFalse(result);
            } else if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll && userSpec.roles.equals(ImmutableList.of("non_dls_role"))) {
                assertTrue(result);
            } else {
                assertFalse(result);
            }
        }

        @Test
        public void alias_static_wildcardNonDls() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("alias_a"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_a2"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            boolean result = subject.isUnrestricted(context, resolvedIndices);

            if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll && userSpec.roles.equals(ImmutableList.of("non_dls_role"))) {
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll
                && userSpec.roles.contains("non_dls_role")
                && indicesSpec.indices.equals(ImmutableList.of("index_b1"))) {
                    // index_b1 is covered neither by dls_role_1 nor dls_role_2, so it is unrestricted when non_dls_role is present
                    assertTrue(result);
                } else {
                    assertFalse(result);
                }
        }

        @Test
        public void alias_wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("alias_a*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_a2"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("alias_a*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            boolean result = subject.isUnrestricted(context, resolvedIndices);

            if (resolvedIndices.getAllIndices().contains("index_b1")) {
                // index_b1 is not covered by any of the above roles, so there should be always a restriction
                assertFalse(result);
            } else if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll && userSpec.roles.equals(ImmutableList.of("non_dls_role"))) {
                assertTrue(result);
            } else {
                assertFalse(result);
            }
        }

        @Test
        public void alias_template() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("alias_${attr.attr_a}"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("index_${attr.attr_a}2"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("alias_${attr.attr_a}")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            boolean result = subject.isUnrestricted(context, resolvedIndices);

            if (userSpec.attributes.isEmpty()) {
                // All roles defined above use attributes. If there are no user attributes, we must get a restricted result.
                assertFalse(result);
            } else if (resolvedIndices.getAllIndices().contains("index_b1")) {
                // index_b1 is not covered by any of the above roles, so there should be always a restriction
                assertFalse(result);
            } else if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result.
                assertTrue(result);
            } else if (!dfmEmptyOverridesAll && userSpec.roles.equals(ImmutableList.of("non_dls_role"))) {
                // For dfmEmptyOverridesAll == false, the presence only non_dls_role must be there for an unrestricted result.
                assertTrue(result);
            } else {
                assertFalse(result);
            }
        }

        @Parameterized.Parameters(name = "{0}; {1}; {2}; {3}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            for (UserSpec userSpec : Arrays.asList(
                new UserSpec("non_dls_role", "non_dls_role"), //
                new UserSpec("dls_role_1", "dls_role_1"), //
                new UserSpec("dls_role_1 and dls_role_2", "dls_role_1", "dls_role_2"), //
                new UserSpec("dls_role_1 and non_dls_role", "dls_role_1", "non_dls_role"), //
                new UserSpec("non_dls_role, attributes", "non_dls_role").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1, attributes", "dls_role_1").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1 and dls_role_2, attributes", "dls_role_1", "dls_role_2").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1 and non_dls_role, attributes", "dls_role_1", "non_dls_role").attribute("attr.attr_a", "a"), //
                new UserSpec("no roles")//
            )) {
                for (IndicesSpec indicesSpec : Arrays.asList(
                    new IndicesSpec("index_a1"), //
                    new IndicesSpec("index_a2"), //
                    new IndicesSpec("index_b1"), //
                    new IndicesSpec("alias_a"), //
                    new IndicesSpec("index_a1", "index_a2"), //
                    new IndicesSpec("index_a1", "index_b1"), //
                    new IndicesSpec("alias_a", "index_b1")
                )) {
                    for (Statefulness statefulness : Statefulness.values()) {
                        for (DfmEmptyOverridesAll dfmEmptyOverridesAll : DfmEmptyOverridesAll.values()) {
                            result.add(new Object[] { userSpec, indicesSpec, statefulness, dfmEmptyOverridesAll });
                        }
                    }
                }
            }
            return result;
        }

        public IndicesAndAliases_isUnrestricted(
            UserSpec userSpec,
            IndicesSpec indicesSpec,
            Statefulness statefulness,
            DfmEmptyOverridesAll dfmEmptyOverridesAll
        ) {
            this.userSpec = userSpec;
            this.indicesSpec = indicesSpec;
            this.user = userSpec.buildUser();
            this.resolvedIndices = RESOLVER_REPLACER.resolveRequest(new IndicesRequest.Replaceable() {

                @Override
                public String[] indices() {
                    return indicesSpec.indices.toArray(new String[0]);
                }

                @Override
                public IndicesOptions indicesOptions() {
                    return IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED;
                }

                @Override
                public IndicesRequest indices(String... strings) {
                    return this;
                }
            });
            this.context = new PrivilegesEvaluationContext(
                this.user,
                ImmutableSet.copyOf(userSpec.roles),
                null,
                null,
                null,
                RESOLVER_REPLACER,
                INDEX_NAME_EXPRESSION_RESOLVER,
                () -> CLUSTER_STATE
            );
            this.statefulness = statefulness;
            this.dfmEmptyOverridesAll = dfmEmptyOverridesAll == DfmEmptyOverridesAll.DFM_EMPTY_OVERRIDES_ALL_TRUE;
        }

        private DocumentPrivileges createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new DocumentPrivileges(
                roleConfig,
                statefulness == Statefulness.STATEFUL ? INDEX_METADATA.getIndicesLookup() : Map.of(),
                xContentRegistry,
                Settings.builder().put("plugins.security.dfm_empty_overrides_all", this.dfmEmptyOverridesAll).build()
            );
        }
    }

    @RunWith(Parameterized.class)
    public static class DataStreams_getRestriction {
        final static Metadata INDEX_METADATA = dataStreams("datastream_a1", "datastream_a2", "datastream_b1", "datastream_b2").build();
        final static ClusterState CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(INDEX_METADATA).build();

        final static IndexAbstraction.Index datastream_a1_backing = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup()
            .get(".ds-datastream_a1-000001");
        final static IndexAbstraction.Index datastream_a2_backing = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup()
            .get(".ds-datastream_a2-000001");
        final static IndexAbstraction.Index datastream_b1_backing = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup()
            .get(".ds-datastream_b1-000001");

        final Statefulness statefulness;
        final UserSpec userSpec;
        final User user;
        final IndexSpec indexSpec;
        final IndexAbstraction.Index index;
        final PrivilegesEvaluationContext context;
        final boolean dfmEmptyOverridesAll;

        @Test
        public void wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result.
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
            } else if (userSpec.roles.contains("dls_role_1")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
            } else if (userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
            } else if (!dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else {
                fail("Unhandled case " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Test
        public void indexPattern() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("datastream_a*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("datastream_b*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("datastream_a*", "datastream_b*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result.
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.roles.contains("dls_role_1") || userSpec.roles.contains("dls_role_2")) {
                if (index == datastream_a1_backing || index == datastream_a2_backing) {
                    if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                } else if (index == datastream_b1_backing) {
                    if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("non_dls_role")) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                }
            } else if (!dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else {
                fail("Unhandled case " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Test
        public void indexPattern_nonDlsRoleOnWildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("datastream_a*"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("datastream_b*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                // For dfmEmptyOverridesAll == true, the presence of non_dls_role alone is sufficient for an unrestricted result.
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.roles.contains("dls_role_1") || userSpec.roles.contains("dls_role_2")) {
                if (index == datastream_a1_backing || index == datastream_a2_backing) {
                    if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                } else if (index == datastream_b1_backing) {
                    if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("non_dls_role")) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                }
            } else if (!dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else {
                fail("Unhandled case " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Test
        public void indexPatternTemplate() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("dls_role_1").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r1"))
                    .on("datastream_${attr.attr_a}1"),
                new TestSecurityConfig.Role("dls_role_2").indexPermissions("*")
                    .dls(QueryBuilders.termQuery("dept", "dept_r2"))
                    .on("datastream_${attr.attr_a}*"),
                new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("datastream_${attr.attr_a}*")
            );

            DocumentPrivileges subject = createSubject(roleConfig);
            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (index == datastream_b1_backing) {
                // This test case never grants privileges to datastream_b1
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.attributes.isEmpty()) {
                // As all the roles in our roleConfig (see above) use user attributes, these won't work with
                // users without attributes. Then, access should be also restricted
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.contains("dls_role_1") || userSpec.roles.contains("dls_role_2")) {
                if (index == datastream_a1_backing) {
                    if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                } else if (index == datastream_a2_backing) {
                    if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                }
            } else if (!dfmEmptyOverridesAll && userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else {
                fail("Unhandled case " + this);
            }

            boolean isUnrestricted = subject.isUnrestricted(context, index.getName());
            if (dlsRestriction.isUnrestricted()) {
                assertTrue("isUnrestricted() should return true according to " + dlsRestriction, isUnrestricted);
            } else {
                assertFalse("isUnrestricted() should return false according to " + dlsRestriction, isUnrestricted);
            }
        }

        @Parameterized.Parameters(name = "{0}; {1}; {2}; {3}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            for (UserSpec userSpec : Arrays.asList(
                new UserSpec("non_dls_role", "non_dls_role"), //
                new UserSpec("dls_role_1", "dls_role_1"), //
                new UserSpec("dls_role_1 and dls_role_2", "dls_role_1", "dls_role_2"), //
                new UserSpec("dls_role_1 and non_dls_role", "dls_role_1", "non_dls_role"), //
                new UserSpec("non_dls_role, attributes", "non_dls_role").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1, attributes", "dls_role_1").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1 and dls_role_2, attributes", "dls_role_1", "dls_role_2").attribute("attr.attr_a", "a"), //
                new UserSpec("dls_role_1 and non_dls_role, attributes", "dls_role", "non_dls_role").attribute("attr.attr_a", "a"), //
                new UserSpec("no roles")//
            )) {
                for (IndexSpec indexSpec : Arrays.asList(
                    new IndexSpec(datastream_a1_backing.getName()), //
                    new IndexSpec(datastream_a2_backing.getName()), //
                    new IndexSpec(datastream_b1_backing.getName())
                )) {
                    for (Statefulness statefulness : Statefulness.values()) {
                        for (DfmEmptyOverridesAll dfmEmptyOverridesAll : DfmEmptyOverridesAll.values()) {
                            result.add(new Object[] { userSpec, indexSpec, statefulness, dfmEmptyOverridesAll });
                        }
                    }
                }
            }
            return result;
        }

        private DocumentPrivileges createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new DocumentPrivileges(
                roleConfig,
                statefulness == Statefulness.STATEFUL ? INDEX_METADATA.getIndicesLookup() : Map.of(),
                xContentRegistry,
                Settings.builder().put("plugins.security.dfm_empty_overrides_all", this.dfmEmptyOverridesAll).build()
            );
        }

        public DataStreams_getRestriction(
            UserSpec userSpec,
            IndexSpec indexSpec,
            Statefulness statefulness,
            DfmEmptyOverridesAll dfmEmptyOverridesAll
        ) {
            this.userSpec = userSpec;
            this.indexSpec = indexSpec;
            this.user = userSpec.buildUser();
            this.index = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get(indexSpec.index);
            this.context = new PrivilegesEvaluationContext(
                this.user,
                ImmutableSet.copyOf(userSpec.roles),
                null,
                null,
                null,
                null,
                null,
                () -> CLUSTER_STATE
            );
            this.statefulness = statefulness;
            this.dfmEmptyOverridesAll = dfmEmptyOverridesAll == DfmEmptyOverridesAll.DFM_EMPTY_OVERRIDES_ALL_TRUE;
        }

    }

    /**
     * Unit tests for the inner class DocumentPrivileges.DlsQuery
     */
    public static class DlsQuery {
        @Test(expected = PrivilegesConfigurationValidationException.class)
        public void invalidQuery() throws Exception {
            DocumentPrivileges.DlsQuery.create("{\"invalid\": \"totally\"}", xContentRegistry);
        }

        @Test(expected = PrivilegesEvaluationException.class)
        public void invalidTemplatedQuery() throws Exception {
            DocumentPrivileges.DlsQuery.create("{\"invalid\": \"totally ${attr.foo}\"}", xContentRegistry)
                .evaluate(new PrivilegesEvaluationContext(new User("test_user"), ImmutableSet.of(), null, null, null, null, null, null));
        }

        @Test
        public void equals() throws Exception {
            DocumentPrivileges.DlsQuery query1a = DocumentPrivileges.DlsQuery.create(
                Strings.toString(MediaTypeRegistry.JSON, QueryBuilders.termQuery("foo", "1")),
                xContentRegistry
            );
            DocumentPrivileges.DlsQuery query1b = DocumentPrivileges.DlsQuery.create(
                Strings.toString(MediaTypeRegistry.JSON, QueryBuilders.termQuery("foo", "1")),
                xContentRegistry
            );
            DocumentPrivileges.DlsQuery query2 = DocumentPrivileges.DlsQuery.create(
                Strings.toString(MediaTypeRegistry.JSON, QueryBuilders.termQuery("foo", "2")),
                xContentRegistry
            );

            assertEquals(query1a, query1b);
            assertNotEquals(query2, query1a);
        }
    }

    static SecurityDynamicConfiguration<RoleV7> roleConfig(TestSecurityConfig.Role... roles) {
        return TestSecurityConfig.Role.toRolesConfiguration(roles);
    }

    public static class UserSpec {
        final List<String> roles;
        final String description;
        final Map<String, String> attributes = new HashMap<>();

        UserSpec(String description, String... roles) {
            this.description = description;
            this.roles = Arrays.asList(roles);
        }

        UserSpec attribute(String name, String value) {
            this.attributes.put(name, value);
            return this;
        }

        User buildUser() {
            User user = new User("test_user_" + description);
            user.addAttributes(this.attributes);
            return user;
        }

        @Override
        public String toString() {
            return this.description;
        }
    }

    public static class IndexSpec {
        final String index;

        IndexSpec(String index) {
            this.index = index;
        }

        @Override
        public String toString() {
            return this.index;
        }
    }

    public static class IndicesSpec {
        final ImmutableList<String> indices;

        IndicesSpec(String... indices) {
            this.indices = ImmutableList.copyOf(indices);
        }

        @Override
        public String toString() {
            return this.indices.toString();
        }
    }

    /**
     * Determines whether the stateful/denormalized data structure shall be created or not.
     */
    static enum Statefulness {
        STATEFUL,
        NON_STATEFUL
    }

    /**
     * Reflects the value of the setting plugins.security.dfm_empty_overrides_all
     */
    static enum DfmEmptyOverridesAll {
        DFM_EMPTY_OVERRIDES_ALL_TRUE,
        DFM_EMPTY_OVERRIDES_ALL_FALSE
    }

    static DiagnosingMatcher<DlsRestriction> isUnrestricted() {
        return new DiagnosingMatcher<DlsRestriction>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A DlsRestriction object that has no restrictions");
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof DlsRestriction)) {
                    mismatchDescription.appendValue(item).appendText(" is not a DlsRestriction object");
                    return false;
                }

                DlsRestriction dlsRestriction = (DlsRestriction) item;

                if (dlsRestriction.isUnrestricted()) {
                    return true;
                } else {
                    mismatchDescription.appendText("The DlsRestriction object is not unrestricted:").appendValue(dlsRestriction);
                    return false;
                }
            }

        };

    }

    @SafeVarargs
    static DiagnosingMatcher<DlsRestriction> isRestricted(Matcher<QueryBuilder>... queries) {
        return new DiagnosingMatcher<DlsRestriction>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A DlsRestriction object that has the restrictions: ")
                    .appendList("", "", ", ", Arrays.asList(queries));
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof DlsRestriction)) {
                    mismatchDescription.appendValue(item).appendText(" is not a DlsRestriction object");
                    return false;
                }

                DlsRestriction dlsRestriction = (DlsRestriction) item;

                if (dlsRestriction.isUnrestricted()) {
                    mismatchDescription.appendText("The DlsRestriction object is not restricted:").appendValue(dlsRestriction);
                    return false;

                }

                Set<Matcher<QueryBuilder>> subMatchers = new HashSet<>(Arrays.asList(queries));
                Set<DocumentPrivileges.RenderedDlsQuery> unmatchedQueries = new HashSet<>(dlsRestriction.getQueries());

                for (DocumentPrivileges.RenderedDlsQuery query : dlsRestriction.getQueries()) {
                    for (Matcher<QueryBuilder> subMatcher : subMatchers) {
                        if (subMatcher.matches(query.getQueryBuilder())) {
                            unmatchedQueries.remove(query);
                            subMatchers.remove(subMatcher);
                            break;
                        }
                    }
                }

                if (unmatchedQueries.isEmpty() && subMatchers.isEmpty()) {
                    return true;
                }

                if (!unmatchedQueries.isEmpty()) {
                    mismatchDescription.appendText("The DlsRestriction contains unexpected queries:")
                        .appendValue(unmatchedQueries)
                        .appendText("\n");
                }

                if (!subMatchers.isEmpty()) {
                    mismatchDescription.appendText("The DlsRestriction does not contain expected queries: ")
                        .appendValue(subMatchers)
                        .appendText("\n");
                }

                return false;
            }

        };
    }

    static DiagnosingMatcher<DlsRestriction> isFullyRestricted() {
        return new DiagnosingMatcher<DlsRestriction>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A DlsRestriction object that has full restrictions");
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof DlsRestriction)) {
                    mismatchDescription.appendValue(item).appendText(" is not a DlsRestriction object");
                    return false;
                }

                DlsRestriction dlsRestriction = (DlsRestriction) item;

                if (dlsRestriction.getQueries().size() != 0) {
                    for (DocumentPrivileges.RenderedDlsQuery query : dlsRestriction.getQueries()) {
                        if (!query.getQueryBuilder().equals(new MatchNoneQueryBuilder())) {
                            mismatchDescription.appendText("The DlsRestriction object is not fully restricted:")
                                .appendValue(dlsRestriction);
                            return false;
                        }
                    }

                    return true;
                } else {
                    mismatchDescription.appendText("The DlsRestriction object is not fully restricted:").appendValue(dlsRestriction);
                    return false;
                }
            }

        };
    }

    static BaseMatcher<QueryBuilder> termQuery(String field, Object value) {
        return new BaseMatcher<QueryBuilder>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A TermQueryBuilder object with ").appendValue(field).appendText("=").appendValue(value);
            }

            @Override
            public boolean matches(Object item) {
                if (!(item instanceof BaseTermQueryBuilder)) {
                    return false;
                }

                BaseTermQueryBuilder<?> queryBuilder = (BaseTermQueryBuilder<?>) item;

                if (queryBuilder.fieldName().equals(field) && queryBuilder.value().equals(value)) {
                    return true;
                } else {
                    return false;
                }
            }
        };
    }

}
