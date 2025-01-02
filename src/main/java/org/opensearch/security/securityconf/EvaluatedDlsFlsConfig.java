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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.support.WildcardMatcher;

public class EvaluatedDlsFlsConfig {
    public static EvaluatedDlsFlsConfig EMPTY = new EvaluatedDlsFlsConfig(
        Collections.emptyMap(),
        Collections.emptyMap(),
        Collections.emptyMap()
    );

    private final Map<String, Set<String>> dlsQueriesByIndex;
    private final Map<String, Set<String>> flsByIndex;
    private final Map<String, Set<String>> fieldMaskingByIndex;

    public EvaluatedDlsFlsConfig(
        Map<String, Set<String>> dlsQueriesByIndex,
        Map<String, Set<String>> flsByIndex,
        Map<String, Set<String>> fieldMaskingByIndex
    ) {
        this.dlsQueriesByIndex = Collections.unmodifiableMap(dlsQueriesByIndex);
        this.flsByIndex = Collections.unmodifiableMap(flsByIndex);
        this.fieldMaskingByIndex = Collections.unmodifiableMap(fieldMaskingByIndex);
    }

    public Map<String, Set<String>> getDlsQueriesByIndex() {
        return dlsQueriesByIndex;
    }

    public Map<String, Set<String>> getFlsByIndex() {
        return flsByIndex;
    }

    public Map<String, Set<String>> getFieldMaskingByIndex() {
        return fieldMaskingByIndex;
    }

    public Set<String> getAllQueries() {
        int mapSize = dlsQueriesByIndex.size();

        if (mapSize == 0) {
            return Collections.emptySet();
        } else if (mapSize == 1) {
            return dlsQueriesByIndex.values().iterator().next();
        } else {
            Set<String> result = new HashSet<>();

            for (Set<String> queries : dlsQueriesByIndex.values()) {
                result.addAll(queries);
            }

            return result;
        }
    }

    public boolean hasFls() {
        return !flsByIndex.isEmpty();
    }

    public boolean hasFieldMasking() {
        return !fieldMaskingByIndex.isEmpty();
    }

    public boolean hasDls() {
        return !dlsQueriesByIndex.isEmpty();
    }

    public boolean isEmpty() {
        return fieldMaskingByIndex.isEmpty() && flsByIndex.isEmpty() && dlsQueriesByIndex.isEmpty();
    }

    public EvaluatedDlsFlsConfig filter(Resolved indices) {
        if (indices.isAllIndicesEmpty()) {
            return EMPTY;
        } else if (this.isEmpty() || indices.isLocalAll()) {
            return this;
        } else {
            Set<String> allIndices = indices.getAllIndices();

            return new EvaluatedDlsFlsConfig(
                filter(dlsQueriesByIndex, allIndices),
                filter(flsByIndex, allIndices),
                filter(fieldMaskingByIndex, allIndices)
            );
        }
    }

    public EvaluatedDlsFlsConfig withoutDls() {
        if (!hasDls()) {
            return this;
        } else {
            return new EvaluatedDlsFlsConfig(Collections.emptyMap(), flsByIndex, fieldMaskingByIndex);
        }
    }

    private Map<String, Set<String>> filter(Map<String, Set<String>> map, Set<String> allIndices) {
        if (allIndices.isEmpty() || map.isEmpty()) {
            return map;
        }

        HashMap<String, Set<String>> result = new HashMap<>(map.size());

        for (Map.Entry<String, Set<String>> entry : map.entrySet()) {
            if (WildcardMatcher.from(entry.getKey(), false).matchAny(allIndices)) {
                result.put(entry.getKey(), entry.getValue());
            }
        }

        return result;
    }

    @Override
    public String toString() {
        return "EvaluatedDlsFlsConfig [dlsQueriesByIndex="
            + dlsQueriesByIndex
            + ", flsByIndex="
            + flsByIndex
            + ", fieldMaskingByIndex="
            + fieldMaskingByIndex
            + "]";
    }

}
