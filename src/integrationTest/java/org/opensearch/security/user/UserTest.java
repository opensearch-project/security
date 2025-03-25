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

import com.google.common.collect.ImmutableMap;
import org.junit.Test;

import org.opensearch.security.support.Base64Helper;

import static org.junit.Assert.assertEquals;

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
        // System.out.println(Base64JDKHelper.serializeObject(user));
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
}
