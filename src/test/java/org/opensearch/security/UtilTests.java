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

package org.opensearch.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.util.Map;

import org.opensearch.security.support.SecurityUtils;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.opensearch.common.settings.Settings;
import org.junit.Test;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

public class UtilTests {

    static private WildcardMatcher wc(String pattern) {
        return WildcardMatcher.from(pattern);
    }

    static private WildcardMatcher iwc(String pattern) {
        return WildcardMatcher.from(pattern, false);
    }

    @Test
    public void testWildcardMatcherClasses() {
        assertFalse(wc("a*?").test("a"));
        assertTrue(wc("a*?").test("aa"));
        assertTrue(wc("a*?").test("ab"));
        assertTrue(wc("a*?").test("abb"));
        assertTrue(wc("*my*index").test("myindex"));
        assertFalse(wc("*my*index").test("myindex1"));
        assertTrue(wc("*my*index?").test("myindex1"));
        assertTrue(wc("*my*index").test("this_is_my_great_index"));
        assertFalse(wc("*my*index").test("MYindex"));
        assertFalse(wc("?kibana").test("kibana"));
        assertTrue(wc("?kibana").test(".kibana"));
        assertFalse(wc("?kibana").test("kibana."));
        assertTrue(wc("?kibana?").test("?kibana."));
        assertTrue(wc("/(\\d{3}-?\\d{2}-?\\d{4})/").test("123-45-6789"));
        assertFalse(wc("(\\d{3}-?\\d{2}-?\\d{4})").test("123-45-6789"));
        assertTrue(wc("/\\S+/").test("abc"));
        assertTrue(wc("abc").test("abc"));
        assertFalse(wc("ABC").test("abc"));
    }

    @Test
    public void testWildcardMatcherClassesCaseInsensitive() {
        assertTrue(iwc("AbC").test("abc"));
        assertTrue(iwc("abc").test("aBC"));
        assertTrue(iwc("A*b").test("ab"));
        assertTrue(iwc("A*b").test("aab"));
        assertTrue(iwc("A*b").test("abB"));
        assertFalse(iwc("abc").test("AB"));
        assertTrue(iwc("/^\\w+$/").test("AbCd"));
    }

    @Test
    public void testWildcardMatchers() {
        assertTrue(!WildcardMatcher.from("a*?").test( "a"));
        assertTrue(WildcardMatcher.from("a*?").test( "aa"));
        assertTrue(WildcardMatcher.from("a*?").test( "ab"));
        //assertTrue(WildcardMatcher.pattern("a*?").test( "abb"));
        assertTrue(WildcardMatcher.from("*my*index").test( "myindex"));
        assertTrue(!WildcardMatcher.from("*my*index").test( "myindex1"));
        assertTrue(WildcardMatcher.from("*my*index?").test( "myindex1"));
        assertTrue(WildcardMatcher.from("*my*index").test( "this_is_my_great_index"));
        assertTrue(!WildcardMatcher.from("*my*index").test( "MYindex"));
        assertTrue(!WildcardMatcher.from("?kibana").test( "kibana"));
        assertTrue(WildcardMatcher.from("?kibana").test( ".kibana"));
        assertTrue(!WildcardMatcher.from("?kibana").test( "kibana."));
        assertTrue(WildcardMatcher.from("?kibana?").test( "?kibana."));
        assertTrue(WildcardMatcher.from("/(\\d{3}-?\\d{2}-?\\d{4})/").test( "123-45-6789"));
        assertTrue(!WildcardMatcher.from("(\\d{3}-?\\d{2}-?\\d{4})").test( "123-45-6789"));
        assertTrue(WildcardMatcher.from("/\\S*/").test( "abc"));
        assertTrue(WildcardMatcher.from("abc").test( "abc"));
        assertTrue(!WildcardMatcher.from("ABC").test( "abc"));
    }

    @Test
    public void testMapFromArray() {
        Map<Object, Object> map = SecurityUtils.mapFromArray((Object)null);
        assertTrue(map == null);
        
        map = SecurityUtils.mapFromArray("key");
        assertTrue(map == null);

        map = SecurityUtils.mapFromArray("key", "value", "otherkey");
        assertTrue(map == null);
        
        map = SecurityUtils.mapFromArray("key", "value");
        assertNotNull(map);        
        assertEquals(1, map.size());
        assertEquals("value", map.get("key"));

        map = SecurityUtils.mapFromArray("key", "value", "key", "value");
        assertNotNull(map);        
        assertEquals(1, map.size());
        assertEquals("value", map.get("key"));

        map = SecurityUtils.mapFromArray("key1", "value1", "key2", "value2");
        assertNotNull(map);        
        assertEquals(2, map.size());
        assertEquals("value1", map.get("key1"));
        assertEquals("value2", map.get("key2"));

    }
    
    @Test
    public void testEnvReplace() {
        Settings settings = Settings.EMPTY;
        assertEquals("abv${env.MYENV}xyz", SecurityUtils.replaceEnvVars("abv${env.MYENV}xyz",settings));
        assertEquals("abv${envbc.MYENV}xyz", SecurityUtils.replaceEnvVars("abv${envbc.MYENV}xyz",settings));
        assertEquals("abvtTtxyz", SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz",settings));
        assertTrue(OpenBSDBCrypt.checkPassword(SecurityUtils.replaceEnvVars("${envbc.MYENV:-tTt}",settings), "tTt".toCharArray()));
        assertEquals("abvtTtxyzxxx", SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${env.MYENV:-xxx}",settings));
        assertTrue(SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${envbc.MYENV:-xxx}",settings).startsWith("abvtTtxyz$2y$"));
        assertEquals("abv${env.MYENV:tTt}xyz", SecurityUtils.replaceEnvVars("abv${env.MYENV:tTt}xyz",settings));
        assertEquals("abv${env.MYENV-tTt}xyz", SecurityUtils.replaceEnvVars("abv${env.MYENV-tTt}xyz",settings));
        //assertEquals("abvabcdefgxyz", SecurityUtils.replaceEnvVars("abv${envbase64.B64TEST}xyz",settings));

        Map<String, String> env = System.getenv();
        assertTrue(env.size() > 0);
        
        boolean checked = false;

        for(String k: env.keySet()) {
            String val=System.getenv().get(k);
            if(val == null || val.isEmpty()) {
                continue;
            }
            assertEquals("abv"+val+"xyz", SecurityUtils.replaceEnvVars("abv${env."+k+"}xyz",settings));
            assertEquals("abv${"+k+"}xyz", SecurityUtils.replaceEnvVars("abv${"+k+"}xyz",settings));
            assertEquals("abv"+val+"xyz", SecurityUtils.replaceEnvVars("abv${env."+k+":-k182765ggh}xyz",settings));
            assertEquals("abv"+val+"xyzabv"+val+"xyz", SecurityUtils.replaceEnvVars("abv${env."+k+"}xyzabv${env."+k+"}xyz",settings));
            assertEquals("abv"+val+"xyz", SecurityUtils.replaceEnvVars("abv${env."+k+":-k182765ggh}xyz",settings));
            assertTrue(OpenBSDBCrypt.checkPassword(SecurityUtils.replaceEnvVars("${envbc."+k+"}",settings), val.toCharArray()));
            checked = true;
        }
        
        assertTrue(checked);
    }
    
    @Test
    public void testNoEnvReplace() {
        Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_DISABLE_ENVVAR_REPLACEMENT, true).build();
        assertEquals("abv${env.MYENV}xyz", SecurityUtils.replaceEnvVars("abv${env.MYENV}xyz",settings));
        assertEquals("abv${envbc.MYENV}xyz", SecurityUtils.replaceEnvVars("abv${envbc.MYENV}xyz",settings));
        assertEquals("abv${env.MYENV:-tTt}xyz", SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz",settings));
        assertEquals("abv${env.MYENV:-tTt}xyz${env.MYENV:-xxx}", SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${env.MYENV:-xxx}",settings));
        assertFalse(SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${envbc.MYENV:-xxx}",settings).startsWith("abvtTtxyz$2y$"));
        assertEquals("abv${env.MYENV:tTt}xyz", SecurityUtils.replaceEnvVars("abv${env.MYENV:tTt}xyz",settings));
        assertEquals("abv${env.MYENV-tTt}xyz", SecurityUtils.replaceEnvVars("abv${env.MYENV-tTt}xyz",settings));
        Map<String, String> env = System.getenv();
        assertTrue(env.size() > 0);
        
        for(String k: env.keySet()) {
            assertEquals("abv${env."+k+"}xyz", SecurityUtils.replaceEnvVars("abv${env."+k+"}xyz",settings));
            assertEquals("abv${"+k+"}xyz", SecurityUtils.replaceEnvVars("abv${"+k+"}xyz",settings));
            assertEquals("abv${env."+k+":-k182765ggh}xyz", SecurityUtils.replaceEnvVars("abv${env."+k+":-k182765ggh}xyz",settings));
            assertEquals("abv${env."+k+"}xyzabv${env."+k+"}xyz", SecurityUtils.replaceEnvVars("abv${env."+k+"}xyzabv${env."+k+"}xyz",settings));
            assertEquals("abv${env."+k+":-k182765ggh}xyz", SecurityUtils.replaceEnvVars("abv${env."+k+":-k182765ggh}xyz",settings));
        }
    }
}
