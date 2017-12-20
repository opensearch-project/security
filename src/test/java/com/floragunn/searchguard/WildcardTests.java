/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard;

import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.support.WildcardMatcher;

public class WildcardTests {
    
    @Test
    public void test() {
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
}
