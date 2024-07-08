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

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;

/**
 * This class pre-computes a flattened/resolved view of all provided action groups. Afterwards, the resolve() method
 * can be used to retrieve the resolved actions with just a lookup instead of an expensive computation.
 *
 * Instead of a recursive algorithm, this class uses a iterative algorithm that terminates as soon as the result set
 * did not change during the previous iteration (i.e., when the result set "settled"). This will also terminate early
 * for loops within the action group definition, as loops do not add any more elements to the result set after the first
 * encounter of them.
 *
 * Still, if the algorithm has not settled after 1000 iterations, it will terminate "early". This will be only the case
 * for nested action group definitions with a nesting level of more than 1000.
 *
 * Instances of this class are immutable. If the action group configuration is updated, a new instance needs to be
 * created.
 */
public class FlattenedActionGroups {
    public static final FlattenedActionGroups EMPTY = new FlattenedActionGroups();

    private static final Logger log = LogManager.getLogger(FlattenedActionGroups.class);

    private final ImmutableMap<String, Set<String>> resolvedActionGroups;

    public FlattenedActionGroups(SecurityDynamicConfiguration<ActionGroupsV7> actionGroups) {
        // Maps action group names to the actions and action groups the particular action group points to
        Map<String, Set<String>> resolved = new HashMap<>(actionGroups.getCEntries().size());

        // Maps action group names to further action group names found in the provided action group configuration.
        // These will need an additional resolution step to resolve recursive definitions.
        Map<String, Set<String>> needsResolution = new HashMap<>(actionGroups.getCEntries().size());

        // First phase: Non-recursive definitions
        //
        // We iterate through all defined action groups and initialize the "resolved" map with the
        // first, non-recursive action group mappings. If we discover that an action group maps to a value which
        // is also a key in the action group config, we know that we have found a recursive definition. This is not
        // yet resolved, but scheduled for resolution by putting the mapping additionally into "needsResolution".
        for (Map.Entry<String, ActionGroupsV7> entry : actionGroups.getCEntries().entrySet()) {
            String key = entry.getKey();

            Set<String> actions = resolved.computeIfAbsent(key, (k) -> new HashSet<>());

            for (String action : entry.getValue().getAllowed_actions()) {
                actions.add(action);

                if (actionGroups.getCEntries().containsKey(action) && !action.equals(key)) {
                    needsResolution.computeIfAbsent(key, (k) -> new HashSet<>()).add(action);
                }
            }
        }

        // Second phase: recursive definitions
        //
        // We iterate through "needsResolution", i.e., the discovered recursive definitions and use the already
        // computed mappings in "resolved" to resolve these recursive definitions. In this course, the mappings in
        // "resolved" grow. As "resolved" might be not complete in the first iteration, we iterate until no further
        // change is observed - only then "resolved" can be considered as complete.
        //
        // Note: "needsResolution" will be not changed in this phase. We certainly will not discover additional
        // recursive definitions. One could argue that it might be possible to remove some entries from "needsResolution"
        // as soon as these are discovered to be complete. But that would require additional copy operations and
        // complicate the algorithm which does not seem to be worth the possible gain.
        boolean settled = false;

        for (int i = 0; !settled; i++) {
            boolean changed = false;

            for (Map.Entry<String, Set<String>> entry : needsResolution.entrySet()) {
                String key = entry.getKey();
                Set<String> resolvedActions = resolved.get(key);

                for (String action : entry.getValue()) {
                    Set<String> mappedActions = resolved.get(action);
                    changed |= resolvedActions.addAll(mappedActions);
                }
            }

            if (!changed) {
                settled = true;
                if (log.isDebugEnabled()) {
                    log.debug("Action groups settled after {} loops.\nResolved: {}", i, resolved);
                }
            }

            if (i >= 1000) {
                log.error("Found too deeply nested action groups. Aborting resolution.\nResolved so far: {}", resolved);
                break;
            }
        }

        this.resolvedActionGroups = ImmutableMap.copyOf(resolved);
    }

    /**
     * Resolves the given list of actions or action groups using the pre-computed flattened index.
     * The result set will always contain AT LEAST the provided elements. IN ADDITION, any elements discovered
     * in the index will be added.
     *
     * Thus, if you provide [a,b] as parameters, and the index contains [b=>1,2], then the result set
     * will contain [a,b,1,2].
     *
     * This method will not perform any pattern matching. It will also not give the strings any semantics based on their
     * contents.
     */
    public ImmutableSet<String> resolve(Collection<String> actions) {
        ImmutableSet.Builder<String> result = ImmutableSet.builder();

        for (String action : actions) {
            if (action == null) {
                continue;
            }

            result.add(action);

            Set<String> mappedActions = this.resolvedActionGroups.get(action);
            if (mappedActions != null) {
                result.addAll(mappedActions);
            }
        }

        return result.build();
    }

    /**
     * Private constructor for creating an empty instance
     */
    private FlattenedActionGroups() {
        this.resolvedActionGroups = ImmutableMap.of();
    }

    @Override
    public String toString() {
        return resolvedActionGroups.toString();
    }

}
