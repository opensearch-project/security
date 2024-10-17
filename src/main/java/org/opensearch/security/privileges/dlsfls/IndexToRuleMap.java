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

import java.util.function.Predicate;

import com.google.common.collect.ImmutableMap;

/**
 * Maps index names to DLS/FLS/FM rules.
 * <p>
 * This only contains index names, not any alias or data stream names.
 * <p>
 * This map should be only used when really necessary, as computing a whole map of indices can be expensive.
 * It should be preferred to directly query the privilege status of indices using the getRestriction() methods
 * of the sub-classes of AbstractRuleBasedPrivileges.
 */
public class IndexToRuleMap<Rule extends AbstractRuleBasedPrivileges.Rule> {
    private static final IndexToRuleMap<?> UNRESTRICTED = new IndexToRuleMap<AbstractRuleBasedPrivileges.Rule>(ImmutableMap.of());

    private final ImmutableMap<String, Rule> indexMap;

    IndexToRuleMap(ImmutableMap<String, Rule> indexMap) {
        this.indexMap = indexMap;
    }

    public boolean isUnrestricted() {
        return this.indexMap.isEmpty() || this.indexMap.values().stream().allMatch(Rule::isUnrestricted);
    }

    public ImmutableMap<String, Rule> getIndexMap() {
        return indexMap;
    }

    public boolean containsAny(Predicate<Rule> predicate) {
        if (indexMap.isEmpty()) {
            return false;
        }

        for (Rule rule : this.indexMap.values()) {
            if (predicate.test(rule)) {
                return true;
            }
        }

        return false;
    }

    @SuppressWarnings("unchecked")
    public static <Rule extends AbstractRuleBasedPrivileges.Rule> IndexToRuleMap<Rule> unrestricted() {
        return (IndexToRuleMap<Rule>) UNRESTRICTED;
    }
}
