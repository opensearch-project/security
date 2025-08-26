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

import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.security.user.User;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UserAttributesUnitTest {
    @Test
    public void testNeedsAttributeSubstitution() {
        assertTrue(UserAttributes.needsAttributeSubstitution("{\"foo\": \"${user.name}}\""));
        assertTrue(UserAttributes.needsAttributeSubstitution("${attr1.proxy.foo}"));
        assertFalse(UserAttributes.needsAttributeSubstitution("{\"foo\": \"bar\"}"));
    }

    @Test
    public void testReplaceProperties() {
        User user = new User("test_user").withAttributes(Map.of("attr.proxy.attr1", "value1"))
            .withSecurityRoles(List.of("role1"))
            .withRoles(List.of("role2"));
        PrivilegesEvaluationContext ctx = new PrivilegesEvaluationContext(
            user,
            ImmutableSet.copyOf(List.of("mapped_role1")),
            null,
            null,
            null,
            null,
            null,
            null,
            null
        );

        String stringWithPlacholders = """
            {
                \"name\": \"${user.name}\",
                \"name2\": \"${user_name}\",
                \"bar\": \"${attr.proxy.attr1}\",
                \"roles\": [${user.roles}],
                \"roles2\": [${user_roles}],
                \"security_roles\": [${user.securityRoles}],
                \"security_roles2\": [${user_securityRoles}],
            }
            """;
        String expectedString = """
            {
                \"name\": \"test_user\",
                \"name2\": \"test_user\",
                \"bar\": \"value1\",
                \"roles\": [\"role2\"],
                \"roles2\": [\"role2\"],
                \"security_roles\": [\"role1\",\"mapped_role1\"],
                \"security_roles2\": [\"role1\",\"mapped_role1\"],
            }
            """;
        assertEquals(expectedString, UserAttributes.replaceProperties(stringWithPlacholders, ctx));
    }
}
