/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityUtils;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;

public class UtilTests {
    
    @Test
    public void testWildcards() {
        Assert.assertTrue(!WildcardMatcher.match("a*?", "a"));
        Assert.assertTrue(WildcardMatcher.match("a*?", "aa"));
        Assert.assertTrue(WildcardMatcher.match("a*?", "ab"));
        //Assert.assertTrue(WildcardMatcher.match("a*?", "abb"));
        Assert.assertTrue(WildcardMatcher.match("*my*index", "myindex"));
        Assert.assertTrue(!WildcardMatcher.match("*my*index", "myindex1"));
        Assert.assertTrue(WildcardMatcher.match("*my*index?", "myindex1"));
        Assert.assertTrue(WildcardMatcher.match("*my*index", "this_is_my_great_index"));
        Assert.assertTrue(!WildcardMatcher.match("*my*index", "MYindex"));
        Assert.assertTrue(!WildcardMatcher.match("?kibana", "kibana"));
        Assert.assertTrue(WildcardMatcher.match("?kibana", ".kibana"));
        Assert.assertTrue(!WildcardMatcher.match("?kibana", "kibana."));
        Assert.assertTrue(WildcardMatcher.match("?kibana?", "?kibana."));
        Assert.assertTrue(WildcardMatcher.match("/(\\d{3}-?\\d{2}-?\\d{4})/", "123-45-6789"));
        Assert.assertTrue(!WildcardMatcher.match("(\\d{3}-?\\d{2}-?\\d{4})", "123-45-6789"));
        Assert.assertTrue(WildcardMatcher.match("/\\S*/", "abc"));
        Assert.assertTrue(WildcardMatcher.match("abc", "abc"));
        Assert.assertTrue(!WildcardMatcher.match("ABC", "abc"));
        Assert.assertTrue(!WildcardMatcher.containsWildcard("abc"));
        Assert.assertTrue(!WildcardMatcher.containsWildcard("abc$"));
        Assert.assertTrue(WildcardMatcher.containsWildcard("abc*"));
        Assert.assertTrue(WildcardMatcher.containsWildcard("a?bc"));
        Assert.assertTrue(WildcardMatcher.containsWildcard("/(\\d{3}-\\d{2}-?\\d{4})/"));
    }

    @Test
    public void testMapFromArray() {
        Map<Object, Object> map = OpenDistroSecurityUtils.mapFromArray((Object)null);
        assertTrue(map == null);
        
        map = OpenDistroSecurityUtils.mapFromArray("key");
        assertTrue(map == null);

        map = OpenDistroSecurityUtils.mapFromArray("key", "value", "otherkey");
        assertTrue(map == null);
        
        map = OpenDistroSecurityUtils.mapFromArray("key", "value");
        assertNotNull(map);        
        assertEquals(1, map.size());
        assertEquals("value", map.get("key"));

        map = OpenDistroSecurityUtils.mapFromArray("key", "value", "key", "value");
        assertNotNull(map);        
        assertEquals(1, map.size());
        assertEquals("value", map.get("key"));

        map = OpenDistroSecurityUtils.mapFromArray("key1", "value1", "key2", "value2");
        assertNotNull(map);        
        assertEquals(2, map.size());
        assertEquals("value1", map.get("key1"));
        assertEquals("value2", map.get("key2"));

    }
}
