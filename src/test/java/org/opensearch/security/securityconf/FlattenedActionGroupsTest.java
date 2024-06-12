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
package org.opensearch.security.securityconf;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;

public class FlattenedActionGroupsTest {
    @Test
    public void basicTest() throws Exception {
        TestActionGroup testActionGroups = new TestActionGroup().with("Z", "C", "A")
            .with("A", "A1", "A2", "A3")
            .with("B", "B1", "B2", "B3")
            .with("C", "A", "B", "C1");
        SecurityDynamicConfiguration<ActionGroupsV7> config = SecurityDynamicConfiguration.fromMap(
            testActionGroups.map,
            CType.ACTIONGROUPS,
            2
        );

        FlattenedActionGroups actionGroups = new FlattenedActionGroups(config);

        Assert.assertEquals(
            ImmutableSet.of("C", "A", "A1", "A2", "A3", "C1", "B", "B1", "B2", "B3", "Z"),
            actionGroups.resolve(ImmutableSet.of("Z"))
        );
        Assert.assertEquals(ImmutableSet.of("A", "A1", "A2", "A3"), actionGroups.resolve(ImmutableSet.of("A")));
    }

    /**
     * This tests an action group definition containing a cycle. Still, the resolution should settle without any
     * stack overflow.
     */
    @Test
    public void cycleTest() throws Exception {
        TestActionGroup testActionGroups = new TestActionGroup().with("A", "A1", "B")
            .with("B", "B1", "C")
            .with("C", "C1", "A", "D")
            .with("D", "D1");
        SecurityDynamicConfiguration<ActionGroupsV7> config = SecurityDynamicConfiguration.fromMap(
            testActionGroups.map,
            CType.ACTIONGROUPS,
            2
        );

        FlattenedActionGroups actionGroups = new FlattenedActionGroups(config);

        Assert.assertEquals(ImmutableSet.of("A", "A1", "B", "B1", "C", "C1", "D", "D1"), actionGroups.resolve(ImmutableSet.of("A")));
        Assert.assertEquals(ImmutableSet.of("A", "A1", "B", "B1", "C", "C1", "D", "D1"), actionGroups.resolve(ImmutableSet.of("C")));
        Assert.assertEquals(ImmutableSet.of("D", "D1"), actionGroups.resolve(ImmutableSet.of("D")));
    }

    private static class TestActionGroup {
        private Map<String, Object> map = new HashMap<>();

        TestActionGroup with(String key, String... actions) {
            map.put(key, ImmutableMap.of("allowed_actions", Arrays.asList(actions)));
            return this;
        }
    }
}
