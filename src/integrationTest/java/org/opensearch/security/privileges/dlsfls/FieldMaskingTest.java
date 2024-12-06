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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.google.common.collect.ImmutableSet;
import org.apache.lucene.util.BytesRef;
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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests on the FieldMasking class - top-level functionality is tested in FieldMaskingTest.Basic. The inner classes FieldMasking.Field
 * and FieldMasking.FieldMaskingRule are tested in the correspondingly named inner test suites.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ FieldMaskingTest.Basic.class, FieldMaskingTest.Field.class, FieldMaskingTest.FieldMaskingRule.class })
public class FieldMaskingTest {

    /**
     * Top-level unit tests on the FieldMasking class. Note: This does just test the full functionality, as most of it
     * is provided by the AbstractRuleBasedPrivileges super-class which is already covered by DocumentPrivilegesTest.
     */
    public static class Basic {
        final static Metadata INDEX_METADATA = //
            indices("index_a1", "index_a2", "index_b1", "index_b2")//
                .alias("alias_a")
                .of("index_a1", "index_a2")//
                .build();

        final static ClusterState CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(INDEX_METADATA).build();

        @Test
        public void indexPattern_simple() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fm_role_1").indexPermissions("*").maskedFields("masked_field_a").on("index_a*")
            );

            FieldMasking subject = createSubject(roleConfig);

            FieldMasking.FieldMaskingRule rule = subject.getRestriction(ctx("fm_role_1"), "index_a1");

            assertEquals(new FieldMasking.FieldMaskingExpression("masked_field_a"), rule.get("masked_field_a").getExpression());
            assertNull("other_field_should be unrestricted", rule.get("other_field"));
        }

        @Test
        public void indexPattern_joined() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fm_role_1").indexPermissions("*").maskedFields("masked_field_a").on("index_a*"),
                new TestSecurityConfig.Role("fm_role_2").indexPermissions("*").maskedFields("masked_field_a1_*").on("index_a1")
            );

            FieldMasking subject = createSubject(roleConfig);

            FieldMasking.FieldMaskingRule rule = subject.getRestriction(ctx("fm_role_1", "fm_role_2"), "index_a1");

            assertEquals(new FieldMasking.FieldMaskingExpression("masked_field_a"), rule.get("masked_field_a").getExpression());
            assertEquals(new FieldMasking.FieldMaskingExpression("masked_field_a1_*"), rule.get("masked_field_a1_x").getExpression());

            assertNull("other_field_should be unrestricted", rule.get("other_field"));
        }

        @Test
        public void indexPattern_unrestricted() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(
                new TestSecurityConfig.Role("fm_role_1").indexPermissions("*").maskedFields("masked_field_a").on("index_a*"),
                new TestSecurityConfig.Role("non_fm_role").indexPermissions("*").on("*")
            );

            FieldMasking subject = createSubject(roleConfig);

            FieldMasking.FieldMaskingRule rule = subject.getRestriction(ctx("fm_role_1", "non_fm_role"), "index_a1");
            assertNull("masked_field_a be unrestricted", rule.get("masked_field_a"));
        }

        static SecurityDynamicConfiguration<RoleV7> roleConfig(TestSecurityConfig.Role... roles) {
            return TestSecurityConfig.Role.toRolesConfiguration(roles);
        }

        static FieldMasking createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new FieldMasking(
                roleConfig,
                INDEX_METADATA.getIndicesLookup(),
                FieldMasking.Config.DEFAULT,
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

    /**
     * Unit tests on the FieldMasking.FieldMaskingRule.Field class.
     */
    public static class Field {
        @Test
        public void simple() throws Exception {
            FieldMasking.FieldMaskingExpression expression = new FieldMasking.FieldMaskingExpression("field_*");
            assertEquals("field_*", expression.getSource());
            assertEquals(WildcardMatcher.from("field_*"), expression.getPattern());
            assertNull(expression.getAlgoName());
            assertNull(expression.getRegexReplacements());

            FieldMasking.FieldMaskingRule.Field field = new FieldMasking.FieldMaskingRule.Field(expression, FieldMasking.Config.DEFAULT);
            assertEquals("96c8d1da7eb153db858d4f0585120319e17ed1162db9e94bee19fb10b6d19727", field.apply("foobar"));
        }

        @Test
        public void simple_deviatingDefaultAlgorithm() throws Exception {
            FieldMasking.FieldMaskingExpression expression = new FieldMasking.FieldMaskingExpression("field_*");
            FieldMasking.FieldMaskingRule.Field field = new FieldMasking.FieldMaskingRule.Field(
                expression,
                FieldMasking.Config.fromSettings(
                    Settings.builder().put("plugins.security.masked_fields.algorithm.default", "SHA-256").build()
                )
            );
            assertEquals("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", field.apply("foobar"));
        }

        @Test
        public void explicitAlgorithm() throws Exception {
            FieldMasking.FieldMaskingExpression expression = new FieldMasking.FieldMaskingExpression("field_*::SHA-256");
            assertEquals(WildcardMatcher.from("field_*"), expression.getPattern());
            assertEquals("SHA-256", expression.getAlgoName());
            assertEquals("field_*::SHA-256", expression.getSource());
            assertNull(expression.getRegexReplacements());

            FieldMasking.FieldMaskingRule.Field field = new FieldMasking.FieldMaskingRule.Field(expression, FieldMasking.Config.DEFAULT);
            assertEquals("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", field.apply("foobar"));
        }

        @Test(expected = PrivilegesConfigurationValidationException.class)
        public void explicitAlgorithm_invalid() throws Exception {
            new FieldMasking.FieldMaskingExpression("field_*::SHADY-777");
        }

        @Test
        public void regex_single() throws Exception {
            FieldMasking.FieldMaskingExpression expression = new FieldMasking.FieldMaskingExpression("field_*::/<secret>/::+masked+");
            assertEquals(WildcardMatcher.from("field_*"), expression.getPattern());
            assertNull(expression.getAlgoName());
            assertEquals(1, expression.getRegexReplacements().size());
            assertEquals("<secret>", expression.getRegexReplacements().get(0).getRegex().toString());
            assertEquals("+masked+", expression.getRegexReplacements().get(0).getReplacement());
            assertEquals("field_*::/<secret>/::+masked+", expression.getSource());
            assertEquals(
                Arrays.asList(new FieldMasking.FieldMaskingExpression.RegexReplacement("/<secret>/", "+masked+")),
                expression.getRegexReplacements()
            );

            FieldMasking.FieldMaskingRule.Field field = new FieldMasking.FieldMaskingRule.Field(expression, FieldMasking.Config.DEFAULT);
            assertEquals("foobar", field.apply("foobar"));
            assertEquals("foo+masked+bar", field.apply("foo<secret>bar"));
        }

        @Test
        public void regex_multi() throws Exception {
            FieldMasking.FieldMaskingExpression expression = new FieldMasking.FieldMaskingExpression(
                "field_*::/<secret>/::+masked+::/\\d/::*"
            );
            assertEquals(WildcardMatcher.from("field_*"), expression.getPattern());
            assertNull(expression.getAlgoName());
            assertEquals(2, expression.getRegexReplacements().size());
            assertEquals("<secret>", expression.getRegexReplacements().get(0).getRegex().toString());
            assertEquals("+masked+", expression.getRegexReplacements().get(0).getReplacement());
            assertEquals("\\d", expression.getRegexReplacements().get(1).getRegex().toString());
            assertEquals("*", expression.getRegexReplacements().get(1).getReplacement());
            assertEquals("field_*::/<secret>/::+masked+::/\\d/::*", expression.getSource());

            FieldMasking.FieldMaskingRule.Field field = new FieldMasking.FieldMaskingRule.Field(expression, FieldMasking.Config.DEFAULT);
            assertEquals("foobar", field.apply("foobar"));
            assertEquals("foo**bar", field.apply("foo42bar"));
            assertEquals("foo+masked+bar**", field.apply("foo<secret>bar42"));
        }

        @Test(expected = PrivilegesConfigurationValidationException.class)
        public void regex_oddParams() throws Exception {
            new FieldMasking.FieldMaskingExpression("field_*::/a/::b::/c/");
        }

        @Test(expected = PrivilegesConfigurationValidationException.class)
        public void regex_invalidRegex() throws Exception {
            new FieldMasking.FieldMaskingExpression("field_*::/a\\/::b");
        }

        @Test(expected = PrivilegesConfigurationValidationException.class)
        public void regex_missingSlashes() throws Exception {
            new FieldMasking.FieldMaskingExpression("field_*::a::b");
        }
    }

    /**
     * Unit tests on the FieldMasking.FieldMaskingRule class.
     */
    public static class FieldMaskingRule {
        @Test
        public void allowAll() {
            assertTrue(
                "FieldMasking.FieldMaskingRule.ALLOW_ALL identifies itself as such",
                FieldMasking.FieldMaskingRule.ALLOW_ALL.isAllowAll()
            );
            assertTrue(
                "FieldMasking.FieldMaskingRule.ALLOW_ALL identifies itself as such",
                FieldMasking.FieldMaskingRule.ALLOW_ALL.isUnrestricted()
            );
            assertFalse("FieldMasking.FieldMaskingRule.ALLOW_ALL allows field", FieldMasking.FieldMaskingRule.ALLOW_ALL.isMasked("field"));
            assertEquals("FM:[]", FieldMasking.FieldMaskingRule.ALLOW_ALL.toString());
        }

        @Test
        public void allowAll_constructed() throws Exception {
            FieldMasking.FieldMaskingRule rule = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT);
            assertTrue("FieldMasking.FieldMaskingRule without masked fields should return true for isAllowAll()", rule.isAllowAll());
            assertFalse("FieldMasking.FieldMaskingRule without masked fields allows field", rule.isMasked("field"));
            assertEquals("FM:[]", rule.toString());
        }

        @Test
        public void simple() throws Exception {
            FieldMasking.FieldMaskingRule rule = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "field_masked_*");
            assertFalse("FieldMasking.FieldMaskingRule should return false for isAllowAll()", rule.isAllowAll());
            assertTrue("Rule applies to field field_masked_1", rule.isMasked("field_masked_1"));
            assertFalse("Rule does not apply to field field_other", rule.isMasked("field_other"));
            assertEquals("96c8d1da7eb153db858d4f0585120319e17ed1162db9e94bee19fb10b6d19727", rule.get("field_masked_1").apply("foobar"));
            assertEquals(
                new BytesRef("96c8d1da7eb153db858d4f0585120319e17ed1162db9e94bee19fb10b6d19727".getBytes(StandardCharsets.UTF_8)),
                rule.get("field_masked_1").apply(new BytesRef("foobar".getBytes(StandardCharsets.UTF_8)))
            );
            assertEquals("FM:[field_masked_*]", rule.toString());
        }

        @Test
        public void keyword() throws Exception {
            FieldMasking.FieldMaskingRule rule = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "field_masked");
            assertFalse("FieldMasking.FieldMaskingRule should return false for isAllowAll()", rule.isAllowAll());
            assertTrue("Rule applies to field field_masked_1", rule.isMasked("field_masked"));
            assertTrue("Rule applies to field field_masked_1.keyword", rule.isMasked("field_masked.keyword"));
            assertEquals(
                "96c8d1da7eb153db858d4f0585120319e17ed1162db9e94bee19fb10b6d19727",
                rule.get("field_masked.keyword").apply("foobar")
            );
        }
    }
}
