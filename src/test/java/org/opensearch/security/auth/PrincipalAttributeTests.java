/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.collections4.trie.PatriciaTrie;
import org.junit.Test;

import org.opensearch.rule.MatchLabel;
import org.opensearch.rule.attribute_extractor.AttributeExtractor;
import org.opensearch.rule.autotagging.Attribute;
import org.opensearch.rule.storage.AttributeValueStore;
import org.opensearch.rule.storage.DefaultAttributeValueStore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PrincipalAttributeTests {

    private static AttributeExtractor<String> extractorFor(String... values) {
        return new AttributeExtractor<>() {
            @Override
            public Attribute getAttribute() {
                return PrincipalAttribute.PRINCIPAL;
            }

            @Override
            public Iterable<String> extract() {
                return List.of(values);
            }

            @Override
            public LogicalOperator getLogicalOperator() {
                return LogicalOperator.OR;
            }
        };
    }

    private static Set<String> featureValues(List<MatchLabel<String>> matches) {
        return matches.stream().map(MatchLabel::getFeatureValue).collect(Collectors.toSet());
    }

    @Test
    public void testExactUsernameStillMatches() {
        AttributeValueStore<String, String> store = new DefaultAttributeValueStore<>(new PatriciaTrie<>());
        store.put("username|alice", "group_a");

        List<MatchLabel<String>> matches = PrincipalAttribute.PRINCIPAL.findAttributeMatches(extractorFor("username|alice"), store);
        assertEquals(Set.of("group_a"), featureValues(matches));
    }

    @Test
    public void testExactUsernameDoesNotPrefixMatch() {
        // A stored value without a trailing wildcard must not match a longer request value.
        AttributeValueStore<String, String> store = new DefaultAttributeValueStore<>(new PatriciaTrie<>());
        store.put("username|dev", "group_a");

        List<MatchLabel<String>> matches = PrincipalAttribute.PRINCIPAL.findAttributeMatches(extractorFor("username|dev_john"), store);
        assertTrue(matches.isEmpty());
    }

    @Test
    public void testWildcardUsernamePrefixMatches() {
        // A stored value ending in '*' prefix-matches request usernames sharing the stem.
        AttributeValueStore<String, String> store = new DefaultAttributeValueStore<>(new PatriciaTrie<>());
        store.put("username|dev*", "group_a");

        assertEquals(
            Set.of("group_a"),
            featureValues(PrincipalAttribute.PRINCIPAL.findAttributeMatches(extractorFor("username|dev"), store))
        );
        assertEquals(
            Set.of("group_a"),
            featureValues(PrincipalAttribute.PRINCIPAL.findAttributeMatches(extractorFor("username|dev_john"), store))
        );
    }

    @Test
    public void testWildcardRoleAppliesRoleWeight() {
        // Role matches are scored by the role subfield weight (0.09), not the username weight.
        AttributeValueStore<String, String> store = new DefaultAttributeValueStore<>(new PatriciaTrie<>());
        store.put("role|admin*", "group_a");

        List<MatchLabel<String>> matches = PrincipalAttribute.PRINCIPAL.findAttributeMatches(extractorFor("role|administrator"), store);
        assertEquals(1, matches.size());
        assertEquals("group_a", matches.get(0).getFeatureValue());
        // request "role|administrator" (18 chars) against stem "role|admin" (10 chars) -> 10/18, times role weight 0.09.
        assertEquals(10f / 18f * 0.09f, matches.get(0).getMatchScore(), 1e-6f);
    }
}
