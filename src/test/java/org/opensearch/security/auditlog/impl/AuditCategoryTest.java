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

package org.opensearch.security.auditlog.impl;

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.opensearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static org.opensearch.security.auditlog.impl.AuditCategory.BAD_HEADERS;

@RunWith(Enclosed.class)
public class AuditCategoryTest {

    @RunWith(Parameterized.class)
    public static class AuditCategoryParseTest {

        private final List<String> input;
        private final EnumSet<AuditCategory> expected;

        public AuditCategoryParseTest(List<String> input, EnumSet<AuditCategory> expected) {
            this.input = input;
            this.expected = expected;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> data() {
            return Arrays.asList(
                new Object[][] {
                    { Arrays.asList(), EnumSet.noneOf(AuditCategory.class) },
                    { Arrays.asList("BAD_HEADERS"), EnumSet.of(BAD_HEADERS) },
                    { Arrays.asList("bad_headers"), EnumSet.of(BAD_HEADERS) },
                    { Arrays.asList("bAd_HeAdErS"), EnumSet.of(BAD_HEADERS) },
                    { Arrays.asList("bAd_HeAdErS"), EnumSet.of(BAD_HEADERS) },
                    { Arrays.asList("BAD_HEADERS", "AUTHENTICATED"), EnumSet.of(BAD_HEADERS, AUTHENTICATED) },
                    {
                        Arrays.asList(
                            "BAD_HEADERS",
                            "FAILED_LOGIN",
                            "MISSING_PRIVILEGES",
                            "GRANTED_PRIVILEGES",
                            "OPENDISTRO_SECURITY_INDEX_ATTEMPT",
                            "SSL_EXCEPTION",
                            "AUTHENTICATED",
                            "INDEX_EVENT",
                            "COMPLIANCE_DOC_READ",
                            "COMPLIANCE_DOC_WRITE",
                            "COMPLIANCE_EXTERNAL_CONFIG",
                            "COMPLIANCE_INTERNAL_CONFIG_READ",
                            "COMPLIANCE_INTERNAL_CONFIG_WRITE"
                        ),
                        EnumSet.allOf(AuditCategory.class) }, }
            );
        }

        @Test
        public void testAuditCategoryEnumSetGenerationWhenEmpty() {
            Set<AuditCategory> categories = AuditCategory.parse(input);
            Assert.assertEquals(categories, expected);
        }
    }

    @RunWith(Parameterized.class)
    public static class AuditCategoryExceptionTest {

        private final List<String> input;

        public AuditCategoryExceptionTest(List<String> input) {
            this.input = input;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> data() {
            return Arrays.asList(
                new Object[][] { { Arrays.asList("BAD_INPUT") }, { Arrays.asList("BAD_HEADERS", "bad_category", "AUTHENTICATED") }, }
            );
        }

        @Test(expected = IllegalArgumentException.class)
        public void testAuditCategoryEnumSetGenerationWhenEmpty() {
            AuditCategory.parse(input);
        }

        @Test(expected = NullPointerException.class)
        public void testNullPointerExceptionForNullInput() {
            AuditCategory.parse(null);
        }
    }
}
