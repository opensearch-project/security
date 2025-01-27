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

import java.util.Arrays;
import java.util.Collections;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.test.framework.TestSecurityConfig;

import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests on the FieldMasking class - top-level functionality is tested in FieldMaskingTest.Basic. The inner classes FieldMasking.Field
 * and FieldMasking.FieldMaskingRule are tested in the correspondingly named inner test suites.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ FieldPrivilegesTest.Basic.class, FieldPrivilegesTest.FlsRule.class, FieldPrivilegesTest.FlsPattern.class })
public class FieldPrivilegesTest {
    public static class Basic {
        final static Metadata INDEX_METADATA = //
            indices("index_a1", "index_a2", "index_b1", "index_b2")//
                .alias("alias_a")
                .of("index_a1", "index_a2")//
                .build();

        final static ClusterState CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(INDEX_METADATA).build();

        @Test
        public void indexPattern_simple_inclusive() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fls_role_1").indexPermissions("*").fls("included_field_a").on("index_a*")
            );

            FieldPrivileges subject = createSubject(roleConfig);

            FieldPrivileges.FlsRule rule = subject.getRestriction(ctx("fls_role_1"), "index_a1");
            assertTrue("included_field_a should be allowed", rule.isAllowed("included_field_a"));
            assertFalse("Fields other than included_field_a should be not allowed", rule.isAllowed("other_field"));
        }

        @Test
        public void indexPattern_simple_exclusive() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fls_role_1").indexPermissions("*").fls("~excluded_field_a").on("index_a*")
            );

            FieldPrivileges subject = createSubject(roleConfig);

            FieldPrivileges.FlsRule rule = subject.getRestriction(ctx("fls_role_1"), "index_a1");
            assertFalse("excluded_field_a should be not allowed", rule.isAllowed("excluded_field_a"));
            assertTrue("Fields other than included_field_a should be allowed", rule.isAllowed("other_field"));
        }

        @Test
        public void indexPattern_joined_inclusive() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fls_role_1").indexPermissions("*").fls("included_field_a").on("index_a*"),
                new TestSecurityConfig.Role("fls_role_2").indexPermissions("*").fls("included_field_a1_*").on("index_a1")
            );

            FieldPrivileges subject = createSubject(roleConfig);

            FieldPrivileges.FlsRule rule = subject.getRestriction(ctx("fls_role_1", "fls_role_2"), "index_a1");
            assertTrue("included_field_a should be allowed", rule.isAllowed("included_field_a"));
            assertTrue("included_field_a1_foo should be allowed", rule.isAllowed("included_field_a1_foo"));
            assertFalse(
                "Fields other than included_field_a and included_field_a1_foo should be not allowed",
                rule.isAllowed("other_field")
            );
        }

        @Test
        public void indexPattern_joined_exclusive() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fls_role_1").indexPermissions("*").fls("~excluded_field_a").on("index_a*"),
                new TestSecurityConfig.Role("fls_role_2").indexPermissions("*").fls("~excluded_field_a1_*").on("index_a1")
            );

            FieldPrivileges subject = createSubject(roleConfig);

            FieldPrivileges.FlsRule rule = subject.getRestriction(ctx("fls_role_1", "fls_role_2"), "index_a1");
            assertFalse("excluded_field_a should be not allowed", rule.isAllowed("excluded_field_a"));
            assertFalse("excluded_field_a1_foo should be not allowed", rule.isAllowed("excluded_field_a1_foo"));
            assertTrue("Fields other than included_field_a and included_field_a1_foo should be allowed", rule.isAllowed("other_field"));
        }

        @Test
        public void indexPattern_unrestricted_inclusive() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fls_role_1").indexPermissions("*").fls("included_field_a").on("index_a*"),
                new TestSecurityConfig.Role("non_fls_role").indexPermissions("*").on("*")
            );

            FieldPrivileges subject = createSubject(roleConfig);

            FieldPrivileges.FlsRule rule = subject.getRestriction(ctx("fls_role_1", "non_fls_role"), "index_a1");
            assertTrue("included_field_a should be allowed", rule.isAllowed("included_field_a"));
            assertTrue("other_field should be allowed", rule.isAllowed("other_field"));
        }

        @Test
        public void indexPattern_unrestricted_exclusive() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fls_role_1").indexPermissions("*").fls("~excluded_field_a").on("index_a*"),
                new TestSecurityConfig.Role("non_fls_role").indexPermissions("*").on("*")
            );

            FieldPrivileges subject = createSubject(roleConfig);

            FieldPrivileges.FlsRule rule = subject.getRestriction(ctx("fls_role_1", "non_fls_role"), "index_a1");
            assertTrue("excluded_field_a should be allowed", rule.isAllowed("excluded_field_a"));
            assertTrue("other_field should be allowed", rule.isAllowed("other_field"));
        }

        static SecurityDynamicConfiguration<RoleV7> roleConfig(TestSecurityConfig.Role... roles) {
            return TestSecurityConfig.Role.toRolesConfiguration(roles);
        }

        static FieldPrivileges createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new FieldPrivileges(
                roleConfig,
                INDEX_METADATA.getIndicesLookup(),
                Settings.builder().put("plugins.security.dfm_empty_overrides_all", true).build()
            );
        }

        static PrivilegesEvaluationContext ctx(String... roles) {
            return new PrivilegesEvaluationContext(
                new User("test_user"),
                ImmutableSet.copyOf(roles),
                null,
                null,
                null,
                null,
                null,
                () -> CLUSTER_STATE
            );
        }
    }

    public static class FlsRule {
        @Test
        public void simple_inclusive() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("field_inclusive");
            assertFalse("FLS rule field_inclusive should be restricted", flsRule.isUnrestricted());
            assertTrue("field_inclusive is allowed", flsRule.isAllowed("field_inclusive"));
            assertFalse("other_field is not allowed", flsRule.isAllowed("other_field"));
            assertEquals("FLS:[field_inclusive]", flsRule.toString());
            assertEquals(Arrays.asList("field_inclusive"), flsRule.getSource());
        }

        @Test
        public void simple_exclusive() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("~field_exclusive");
            assertFalse("FLS rule field_exclusive should be restricted", flsRule.isUnrestricted());
            assertFalse("field_exclusive is not allowed", flsRule.isAllowed("field_exclusive"));
            assertTrue("other_field is allowed", flsRule.isAllowed("other_field"));
        }

        @Test
        public void multi_inclusive() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("field_inclusive_1", "field_inclusive_2");
            assertFalse("FLS rule should be restricted", flsRule.isUnrestricted());
            assertTrue("field_inclusive_1 is allowed", flsRule.isAllowed("field_inclusive_1"));
            assertTrue("field_inclusive_2 is allowed", flsRule.isAllowed("field_inclusive_2"));
            assertFalse("other_field is not allowed", flsRule.isAllowed("other_field"));
        }

        @Test
        public void multi_exclusive() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("~field_exclusive_1", "~field_exclusive_2");
            assertFalse("FLS rule should be restricted", flsRule.isUnrestricted());
            assertFalse("field_exclusive_1 is not allowed", flsRule.isAllowed("field_exclusive_1"));
            assertFalse("field_exclusive_1 is not allowed", flsRule.isAllowed("field_exclusive_2"));
            assertTrue("other_field is allowed", flsRule.isAllowed("other_field"));
        }

        @Test
        public void multi_mixed() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("field_inclusive_1", "~field_exclusive_1");
            // This is one of the weird parts. This just REPLICATES the old behavior for backwards compat.
            // The behavior is undocumented - if there are exclusions and inclusions, only exclusions are regarded.
            // It might make sense to re-think this behavior.
            assertFalse("FLS rule should be restricted", flsRule.isUnrestricted());
            assertFalse("field_exclusive_1 is not allowed", flsRule.isAllowed("field_exclusive_1"));
            assertTrue("other_field is allowed", flsRule.isAllowed("other_field"));
        }

        @Test
        public void nested_inclusive() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("a.b.c");
            assertFalse("FLS rule should be restricted", flsRule.isUnrestricted());
            assertTrue("a.b.c is allowed", flsRule.isAllowed("a.b.c"));
            assertFalse("a.b is not allowed for non-objects", flsRule.isAllowed("a.b"));
            assertTrue("a.b is not allowed for objects", flsRule.isObjectAllowed("a.b"));
            assertFalse("other_field is not allowed", flsRule.isAllowed("other_field"));
            assertFalse("a.b.other_field is not allowed", flsRule.isAllowed("a.b.other_field"));
        }

        @Test
        public void nested_exclusive() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("~a.b.c");
            assertFalse("FLS rule should be restricted", flsRule.isUnrestricted());
            assertFalse("a.b.c is not allowed", flsRule.isAllowed("a.b.c"));
            assertTrue("a.b is allowed", flsRule.isAllowed("a.b"));
            assertTrue("a.b is allowed for objects", flsRule.isObjectAllowed("a.b"));
        }

        @Test
        public void wildcard_inclusive() throws Exception {
            FieldPrivileges.FlsRule flsRule = FieldPrivileges.FlsRule.of("*");
            assertTrue("FLS rule * is unrestricted", flsRule.isUnrestricted());
            assertTrue("anything is allowed", flsRule.isAllowed("anything"));
            assertEquals("FLS:*", flsRule.toString());
        }

    }

    public static class FlsPattern {
        @Test
        public void simple_inclusive() throws Exception {
            FieldPrivileges.FlsPattern flsPattern = new FieldPrivileges.FlsPattern("field_inclusive");
            assertFalse("field_inclusive should be not excluded", flsPattern.isExcluded());
            assertEquals(WildcardMatcher.from("field_inclusive"), flsPattern.getPattern());
            assertEquals("field_inclusive", flsPattern.getSource());
            assertEquals(Collections.emptyList(), flsPattern.getParentObjectPatterns());
        }

        @Test
        public void simple_exclusive() throws Exception {
            FieldPrivileges.FlsPattern flsPattern = new FieldPrivileges.FlsPattern("~field_exclusive");
            assertTrue("field_exclusive should be excluded", flsPattern.isExcluded());
            assertEquals(WildcardMatcher.from("field_exclusive"), flsPattern.getPattern());
            assertEquals("~field_exclusive", flsPattern.getSource());
            assertEquals(Collections.emptyList(), flsPattern.getParentObjectPatterns());
        }

        @Test
        public void simple_exclusive2() throws Exception {
            FieldPrivileges.FlsPattern flsPattern = new FieldPrivileges.FlsPattern("!field_exclusive");
            assertTrue("field_exclusive should be excluded", flsPattern.isExcluded());
            assertEquals(WildcardMatcher.from("field_exclusive"), flsPattern.getPattern());
            assertEquals("!field_exclusive", flsPattern.getSource());
            assertEquals(Collections.emptyList(), flsPattern.getParentObjectPatterns());
        }

        @Test
        public void nested_inclusive() throws Exception {
            FieldPrivileges.FlsPattern flsPattern = new FieldPrivileges.FlsPattern("a.b.c_inclusive");
            assertEquals(WildcardMatcher.from("a.b.c_inclusive"), flsPattern.getPattern());
            assertEquals(
                Arrays.asList(new FieldPrivileges.FlsPattern("a"), new FieldPrivileges.FlsPattern("a.b")),
                flsPattern.getParentObjectPatterns()
            );
        }

        @Test
        public void nested_exclusive() throws Exception {
            FieldPrivileges.FlsPattern flsPattern = new FieldPrivileges.FlsPattern("~a.b.c_exclusive");
            assertTrue("a.b.c_exclusive should be excluded", flsPattern.isExcluded());
            assertEquals(WildcardMatcher.from("a.b.c_exclusive"), flsPattern.getPattern());
            // Exclusive patterns do not need an explicit inclusion of the parent objects. Thus, we get an empty list here
            assertEquals(Collections.emptyList(), flsPattern.getParentObjectPatterns());
        }

        @Test(expected = PrivilegesConfigurationValidationException.class)
        public void invalidRegex() throws Exception {
            new FieldPrivileges.FlsPattern("/a\\/");
        }
    }
}
