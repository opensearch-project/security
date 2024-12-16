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

package org.opensearch.security.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.util.ParsingUtils.safeMapList;
import static org.opensearch.security.util.ParsingUtils.safeStringList;
import static org.junit.Assert.assertThrows;

public class ParsingUtilsTest {

    @Test
    public void testSafeStringList() {
        List<String> emptyResult = safeStringList(null, "test_field");
        assertThat(emptyResult, is(Collections.emptyList()));

        List<String> result = safeStringList(Arrays.asList("test1", "test2"), "test_field");
        assertThat(result, is(Arrays.asList("test1", "test2")));

        // Not a list
        assertThrows(IllegalArgumentException.class, () -> safeStringList("not a list", "test_field"));

        // List with non-string
        assertThrows(IllegalArgumentException.class, () -> safeStringList(Arrays.asList("test", 123), "test_field"));
    }

    @Test
    public void testSafeMapList() {
        List<Map<String, Object>> emptyResult = safeMapList(null, "test_field");
        assertThat(emptyResult, is(Collections.emptyList()));

        Map<String, Object> map1 = new HashMap<>();
        map1.put("key1", "value1");
        map1.put("key2", 123);

        Map<String, Object> map2 = new HashMap<>();
        map2.put("key3", "value3");
        map2.put("key4", true);

        List<Map<String, Object>> input = Arrays.asList(map1, map2);
        List<Map<String, Object>> result = safeMapList(input, "test_field");
        assertThat(result, is(input));

        // Test not a list
        assertThrows(IllegalArgumentException.class, () -> safeMapList("not a list", "test_field"));

        // Test list with non-map element
        assertThrows(IllegalArgumentException.class, () -> safeMapList(Arrays.asList(map1, "not a map"), "test_field"));

        List<Map<String, Object>> list = safeMapList(Arrays.asList(map1, map2), "test_field");
        assertThat(list.size(), is(2));
        assertThat(list.contains(map1), is(true));
        assertThat(list.contains(map2), is(true));

    }

}
