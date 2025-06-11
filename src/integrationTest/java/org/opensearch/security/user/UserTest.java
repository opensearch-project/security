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
package org.opensearch.security.user;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.security.support.Base64Helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

public class UserTest {
    @Test
    public void serialization() {
        User user = new User("serialization_test_user").withRoles(Arrays.asList("br1", "br2", "br3"))
            .withSecurityRoles(Arrays.asList("sr1", "sr2"))
            .withAttributes(ImmutableMap.of("a", "v_a", "b", "v_b"));

        String serialized = Base64Helper.serializeObject(user);
        User user2 = User.fromSerializedBase64(serialized);
        assertEquals(user, user2);

    }

    @Test
    public void deserializationFrom2_19() {
        // The following base64 string was produced by the following code on OpenSearch 2.19
        // User user = new User("serialization_test_user");
        // user.addRoles(Arrays.asList("br1", "br2", "br3"));
        // user.addSecurityRoles(Arrays.asList("sr1", "sr2"));
        // user.addAttributes(ImmutableMap.of("a", "v_a", "b", "v_b"));
        // println(Base64JDKHelper.serializeObject(user));
        String serialized =
            "rO0ABXNyACFvcmcub3BlbnNlYXJjaC5zZWN1cml0eS51c2VyLlVzZXKzqL2T65dH3AIABloACmlzSW5qZWN0ZWRMAAphdHRyaWJ1dGVzdAAPTGphdmEvdXRpbC9NYXA7TAAEbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAD3JlcXVlc3RlZFRlbmFudHEAfgACTAAFcm9sZXN0AA9MamF2YS91dGlsL1NldDtMAA1zZWN1cml0eVJvbGVzcQB+AAN4cABzcgAlamF2YS51dGlsLkNvbGxlY3Rpb25zJFN5bmNocm9uaXplZE1hcBtz+QlLSzl7AwACTAABbXEAfgABTAAFbXV0ZXh0ABJMamF2YS9sYW5nL09iamVjdDt4cHNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAN3CAAAAAQAAAACdAABYXQAA3ZfYXQAAWJ0AAN2X2J4cQB+AAd4dAAXc2VyaWFsaXphdGlvbl90ZXN0X3VzZXJwc3IAJWphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRTZXQGw8J5Au7fPAIAAHhyACxqYXZhLnV0aWwuQ29sbGVjdGlvbnMkU3luY2hyb25pemVkQ29sbGVjdGlvbiph+E0JnJm1AwACTAABY3QAFkxqYXZhL3V0aWwvQ29sbGVjdGlvbjtMAAVtdXRleHEAfgAGeHBzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAN0AANicjF0AANicjN0AANicjJ4cQB+ABJ4c3EAfgAPc3EAfgATdwwAAAAQP0AAAAAAAAJ0AANzcjJ0AANzcjF4cQB+ABh4";

        User user = User.fromSerializedBase64(serialized);
        assertEquals(
            new User("serialization_test_user").withRoles(Arrays.asList("br1", "br2", "br3"))
                .withSecurityRoles(Arrays.asList("sr1", "sr2"))
                .withAttributes(ImmutableMap.of("a", "v_a", "b", "v_b")),
            user
        );
    }

    @Test
    public void deserializationLdapUserFrom2_19() {
        // The following base64 string was produced by the following code on OpenSearch 2.19
        // LdapUser user = new LdapUser("serialization_test_user",
        // "original_user_name",
        // new LdapEntry("cn=test,ou=people,o=TEST", new LdapAttribute("test_ldap_attr", "test_ldap_attr_value")),
        // new AuthCredentials("test_user", "secret".getBytes(StandardCharsets.UTF_8)),
        // 100,
        // WildcardMatcher.ANY);
        // user.addRoles(Arrays.asList("br1", "br2", "br3"));
        // user.addSecurityRoles(Arrays.asList("sr1", "sr2"));
        // user.addAttributes(ImmutableMap.of("a", "v_a", "b", "v_b"));
        // println(Base64JDKHelper.serializeObject(user));
        String serialized =
            "rO0ABXNyACJjb20uYW1hem9uLmRsaWMuYXV0aC5sZGFwLkxkYXBVc2VyAAAAAAAAAAECAAFMABBvcmlnaW5hbFVzZXJuYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7eHIAIW9yZy5vcGVuc2VhcmNoLnNlY3VyaXR5LnVzZXIuVXNlcrOovZPrl0fcAgAGWgAKaXNJbmplY3RlZEwACmF0dHJpYnV0ZXN0AA9MamF2YS91dGlsL01hcDtMAARuYW1lcQB+AAFMAA9yZXF1ZXN0ZWRUZW5hbnRxAH4AAUwABXJvbGVzdAAPTGphdmEvdXRpbC9TZXQ7TAANc2VjdXJpdHlSb2xlc3EAfgAEeHAAc3IAJWphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRNYXAbc/kJS0s5ewMAAkwAAW1xAH4AA0wABW11dGV4dAASTGphdmEvbGFuZy9PYmplY3Q7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAGdwgAAAAIAAAABXQAB2xkYXAuZG50ABhjbj10ZXN0LG91PXBlb3BsZSxvPVRFU1R0AAFhdAADdl9hdAAYYXR0ci5sZGFwLnRlc3RfbGRhcF9hdHRydAAUdGVzdF9sZGFwX2F0dHJfdmFsdWV0AAFidAADdl9idAAWbGRhcC5vcmlnaW5hbC51c2VybmFtZXQAEm9yaWdpbmFsX3VzZXJfbmFtZXhxAH4ACHh0ABdzZXJpYWxpemF0aW9uX3Rlc3RfdXNlcnBzcgAlamF2YS51dGlsLkNvbGxlY3Rpb25zJFN5bmNocm9uaXplZFNldAbDwnkC7t88AgAAeHIALGphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRDb2xsZWN0aW9uKmH4TQmcmbUDAAJMAAFjdAAWTGphdmEvdXRpbC9Db2xsZWN0aW9uO0wABW11dGV4cQB+AAd4cHNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAABA/QAAAAAAAA3QAA2JyMXQAA2JyM3QAA2JyMnhxAH4AGXhzcQB+ABZzcQB+ABp3DAAAABA/QAAAAAAAAnQAA3NyMnQAA3NyMXhxAH4AH3hxAH4AFA==";

        User user = User.fromSerializedBase64(serialized);
        assertEquals(
            new User("serialization_test_user").withRoles(Arrays.asList("br1", "br2", "br3"))
                .withSecurityRoles(Arrays.asList("sr1", "sr2"))
                .withAttributes(ImmutableMap.of("a", "v_a", "b", "v_b")),
            user
        );
    }

    @Test
    public void withRoles() {
        User original = new User("test_user").withRoles("a");
        User modified = original.withRoles("b");

        assertEquals(ImmutableSet.of("a"), original.getRoles());
        assertEquals(ImmutableSet.of("a", "b"), modified.getRoles());
    }

    @Test
    public void withRoles_unmodified() {
        User original = new User("test_user").withRoles("a");
        User unmodified = original.withRoles(ImmutableSet.of());

        assertSame(original, unmodified);
    }

    @Test
    public void withAttributes() {
        User original = new User("test_user").withAttributes(Map.of("a", "1"));
        User modified = original.withAttributes(Map.of("b", "2"));

        assertEquals(ImmutableMap.of("a", "1"), original.getCustomAttributesMap());
        assertEquals(ImmutableMap.of("a", "1", "b", "2"), modified.getCustomAttributesMap());
    }

    @Test
    public void withAttributes_unmodified() {
        User original = new User("test_user").withAttributes(Map.of("a", "1"));
        User unmodified = original.withAttributes(Map.of());

        assertSame(original, unmodified);
    }

    @Test
    public void withRequestedTenant() {
        User original = new User("test_user").withRequestedTenant("a");
        User modified = original.withRequestedTenant("b");

        assertEquals("a", original.getRequestedTenant());
        assertEquals("b", modified.getRequestedTenant());
    }

    @Test
    public void withRequestedTenant_unmodified() {
        User original = new User("test_user").withRequestedTenant("a");
        User unmodified = original.withRequestedTenant("a");

        assertSame(original, unmodified);
    }

    @Test(expected = IllegalArgumentException.class)
    public void illegalName() {
        new User("");
    }
}
