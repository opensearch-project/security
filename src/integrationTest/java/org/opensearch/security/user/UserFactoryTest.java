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
import java.util.Collection;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class UserFactoryTest {
    UserFactory subject;

    @Test
    public void parse_successful() {
        User source = new User("test_user").withRoles(ImmutableSet.of("a", "b"));
        User target = subject.fromSerializedBase64(source.toSerializedBase64());

        assertEquals(source, target);
    }

    @Test
    public void parse_invalid() {
        try {
            User target = subject.fromSerializedBase64("invaliddata123");
            fail("Should have failed; got " + target);
        } catch (Exception e) {
            assertTrue(
                "Got invalid stream header " + e,
                e instanceof OpenSearchException && e.getMessage().contains("invalid stream header")
            );
        }
    }

    public UserFactoryTest(UserFactory subject, String name) {
        this.subject = subject;
    }

    @Parameterized.Parameters(name = "{1}")
    public static Collection<Object[]> params() {
        return Arrays.asList(
            new Object[] { new UserFactory.Simple(), "Simple" },
            new Object[] { new UserFactory.Caching(Settings.EMPTY), "Caching" }
        );
    }
}
