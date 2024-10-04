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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class FlattenedActionGroupsTest {
    @Test
    public void basicTest() throws Exception {
        TestActionGroups testActionGroups = new TestActionGroups(
            new TestActionGroup("Z").members("C", "A"), // C and A are defined below
            new TestActionGroup("A").members("A1", "A2", "A3"), // A1-A3 are leafs
            new TestActionGroup("B").members("B1", "B2", "B3"), // B1-B3 are leafs
            new TestActionGroup("C").members("A", "B", "C1") // A and B are defined above, C1 is leaf
        );
        SecurityDynamicConfiguration<ActionGroupsV7> config = SecurityDynamicConfiguration.fromMap(
            testActionGroups.map,
            CType.ACTIONGROUPS
        );

        FlattenedActionGroups actionGroups = new FlattenedActionGroups(config);

        assertThat(
            ImmutableSet.of("C", "A", "A1", "A2", "A3", "C1", "B", "B1", "B2", "B3", "Z"),
            is(actionGroups.resolve(ImmutableSet.of("Z")))
        );
        assertThat(actionGroups.resolve(ImmutableSet.of("A")), is(ImmutableSet.of("A", "A1", "A2", "A3")));
    }

    /**
     * This tests an action group definition containing a cycle. Still, the resolution should settle without any
     * stack overflow.
     */
    @Test
    public void cycleTest() throws Exception {
        TestActionGroups testActionGroups = new TestActionGroups(
            new TestActionGroup("A").members("A1", "B"), // A1 is leaf, B is defined below
            new TestActionGroup("B").members("B1", "C"), // B1 is leaf, C is defined below
            new TestActionGroup("C").members("C1", "A", "D"), // C1 is leaf, A is defined above (closes cycle)
            new TestActionGroup("D").members("D1") // D1 is leaf
        );

        SecurityDynamicConfiguration<ActionGroupsV7> config = SecurityDynamicConfiguration.fromMap(
            testActionGroups.map,
            CType.ACTIONGROUPS
        );

        FlattenedActionGroups actionGroups = new FlattenedActionGroups(config);

        assertThat(actionGroups.resolve(ImmutableSet.of("A")), is(ImmutableSet.of("A", "A1", "B", "B1", "C", "C1", "D", "D1")));
        assertThat(actionGroups.resolve(ImmutableSet.of("C")), is(ImmutableSet.of("A", "A1", "B", "B1", "C", "C1", "D", "D1")));
        assertThat(actionGroups.resolve(ImmutableSet.of("D")), is(ImmutableSet.of("D", "D1")));
    }

    private static class TestActionGroups {
        private Map<String, Object> map = new HashMap<>();

        TestActionGroups(TestActionGroup... groups) {
            for (TestActionGroup testActionGroup : groups) {
                this.with(testActionGroup);
            }
        }

        TestActionGroups with(TestActionGroup testActionGroup) {
            map.put(testActionGroup.name, ImmutableMap.of("allowed_actions", testActionGroup.members));
            return this;
        }
    }

    private static class TestActionGroup {

        final String name;
        final List<String> members = new ArrayList<>();

        TestActionGroup(String name) {
            this.name = name;
        }

        TestActionGroup members(String... members) {
            this.members.addAll(Arrays.asList(members));
            return this;
        }
    }
}
