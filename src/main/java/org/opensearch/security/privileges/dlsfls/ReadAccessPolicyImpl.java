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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.opensearch.action.support.ReadAccessPolicy;
import org.opensearch.index.query.QueryBuilder;

/** Security's immutable implementation of a grouped read-access policy. */
public final class ReadAccessPolicyImpl implements ReadAccessPolicy {

    private final List<IndexGroup> indexGroups;
    private final Set<String> coveredConcreteIndices;
    private final Map<String, Optional<QueryBuilder>> restrictionsByIndex;
    private final boolean hasRestrictions;

    public ReadAccessPolicyImpl(
        Map<? extends QueryBuilder, ? extends Collection<String>> indicesByRestriction,
        Collection<String> unrestrictedIndices
    ) {
        Objects.requireNonNull(indicesByRestriction, "indicesByRestriction must not be null");
        Objects.requireNonNull(unrestrictedIndices, "unrestrictedIndices must not be null");

        List<IndexGroup> groups = new ArrayList<>();
        Set<String> covered = new LinkedHashSet<>();
        Map<String, Optional<QueryBuilder>> byIndex = new LinkedHashMap<>();
        for (Map.Entry<? extends QueryBuilder, ? extends Collection<String>> entry : indicesByRestriction.entrySet()) {
            addGroup(groups, covered, byIndex, entry.getValue(), Optional.of(Objects.requireNonNull(entry.getKey())));
        }
        if (unrestrictedIndices.isEmpty() == false) {
            addGroup(groups, covered, byIndex, unrestrictedIndices, Optional.empty());
        }

        this.indexGroups = List.copyOf(groups);
        this.coveredConcreteIndices = Collections.unmodifiableSet(covered);
        this.restrictionsByIndex = Collections.unmodifiableMap(byIndex);
        this.hasRestrictions = indicesByRestriction.isEmpty() == false;
    }

    @Override
    public boolean hasRestrictions() {
        return hasRestrictions;
    }

    @Override
    public Set<String> coveredConcreteIndices() {
        return coveredConcreteIndices;
    }

    @Override
    public Optional<QueryBuilder> restrictionsForIndex(String concreteIndex) {
        return restrictionsByIndex.getOrDefault(Objects.requireNonNull(concreteIndex), Optional.empty());
    }

    @Override
    public Collection<IndexGroup> indexGroups() {
        return indexGroups;
    }

    private static void addGroup(
        List<IndexGroup> groups,
        Set<String> covered,
        Map<String, Optional<QueryBuilder>> restrictionsByIndex,
        Collection<String> concreteIndices,
        Optional<QueryBuilder> restrictions
    ) {
        IndexGroup group = new IndexGroupImpl(concreteIndices, restrictions);
        for (String index : group.concreteIndices()) {
            if (covered.add(index) == false) {
                throw new IllegalArgumentException("Concrete index [" + index + "] occurs in more than one index group");
            }
            restrictionsByIndex.put(index, restrictions);
        }
        groups.add(group);
    }

    private static final class IndexGroupImpl implements IndexGroup {
        private final Set<String> concreteIndices;
        private final Optional<QueryBuilder> restrictions;

        private IndexGroupImpl(Collection<String> concreteIndices, Optional<QueryBuilder> restrictions) {
            Objects.requireNonNull(concreteIndices, "concreteIndices must not be null");
            if (concreteIndices.isEmpty()) {
                throw new IllegalArgumentException("An index group must contain at least one concrete index");
            }
            LinkedHashSet<String> copiedIndices = new LinkedHashSet<>();
            for (String index : concreteIndices) {
                copiedIndices.add(Objects.requireNonNull(index, "concrete index must not be null"));
            }
            this.concreteIndices = Collections.unmodifiableSet(copiedIndices);
            this.restrictions = Objects.requireNonNull(restrictions, "restrictions must not be null");
        }

        @Override
        public Set<String> concreteIndices() {
            return concreteIndices;
        }

        @Override
        public Optional<QueryBuilder> restrictions() {
            return restrictions;
        }
    }
}
