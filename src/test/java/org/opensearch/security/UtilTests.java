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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security;

import java.util.Map;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityUtils;
import org.opensearch.security.support.WildcardMatcher;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UtilTests {

    static private WildcardMatcher wc(String pattern) {
        return WildcardMatcher.from(pattern);
    }

    static private WildcardMatcher iwc(String pattern) {
        return WildcardMatcher.from(pattern, false);
    }

    static private final PasswordHasher passwordHasher = PasswordHasherFactory.createPasswordHasher(
        Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT).build()
    );

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
        assertFalse(wc(null).test("abc"));
        assertTrue(WildcardMatcher.from(null, "abc").test("abc"));
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
        assertTrue(!WildcardMatcher.from("a*?").test("a"));
        assertTrue(WildcardMatcher.from("a*?").test("aa"));
        assertTrue(WildcardMatcher.from("a*?").test("ab"));
        // assertTrue(WildcardMatcher.pattern("a*?").test( "abb"));
        assertTrue(WildcardMatcher.from("*my*index").test("myindex"));
        assertTrue(!WildcardMatcher.from("*my*index").test("myindex1"));
        assertTrue(WildcardMatcher.from("*my*index?").test("myindex1"));
        assertTrue(WildcardMatcher.from("*my*index").test("this_is_my_great_index"));
        assertTrue(!WildcardMatcher.from("*my*index").test("MYindex"));
        assertTrue(!WildcardMatcher.from("?kibana").test("kibana"));
        assertTrue(WildcardMatcher.from("?kibana").test(".kibana"));
        assertTrue(!WildcardMatcher.from("?kibana").test("kibana."));
        assertTrue(WildcardMatcher.from("?kibana?").test("?kibana."));
        assertTrue(WildcardMatcher.from("/(\\d{3}-?\\d{2}-?\\d{4})/").test("123-45-6789"));
        assertTrue(!WildcardMatcher.from("(\\d{3}-?\\d{2}-?\\d{4})").test("123-45-6789"));
        assertTrue(WildcardMatcher.from("/\\S*/").test("abc"));
        assertTrue(WildcardMatcher.from("abc").test("abc"));
        assertTrue(!WildcardMatcher.from("ABC").test("abc"));
    }

    @Test
    public void testEnvReplace() {
        Settings settings = Settings.EMPTY;
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV}xyz", settings), is("abv${env.MYENV}xyz"));
        assertThat(SecurityUtils.replaceEnvVars("abv${envbc.MYENV}xyz", settings), is("abv${envbc.MYENV}xyz"));
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz", settings), is("abvtTtxyz"));
        assertTrue(passwordHasher.check("tTt".toCharArray(), SecurityUtils.replaceEnvVars("${envbc.MYENV:-tTt}", settings)));
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${env.MYENV:-xxx}", settings), is("abvtTtxyzxxx"));
        assertTrue(SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${envbc.MYENV:-xxx}", settings).startsWith("abvtTtxyz$2y$"));
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV:tTt}xyz", settings), is("abv${env.MYENV:tTt}xyz"));
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV-tTt}xyz", settings), is("abv${env.MYENV-tTt}xyz"));
        // assertThat(SecurityUtils.replaceEnvVars("abv${envbase64.B64TEST}xyz",settings), is("abvabcdefgxyz"));

        Map<String, String> env = System.getenv();
        assertTrue(env.size() > 0);

        boolean checked = false;

        for (String k : env.keySet()) {
            String val = System.getenv().get(k);
            if (val == null || val.isEmpty()) {
                continue;
            }
            assertThat(SecurityUtils.replaceEnvVars("abv${env." + k + "}xyz", settings), is("abv" + val + "xyz"));
            assertThat(SecurityUtils.replaceEnvVars("abv${" + k + "}xyz", settings), is("abv${" + k + "}xyz"));
            assertThat(SecurityUtils.replaceEnvVars("abv${env." + k + ":-k182765ggh}xyz", settings), is("abv" + val + "xyz"));
            assertThat(
                SecurityUtils.replaceEnvVars("abv${env." + k + "}xyzabv${env." + k + "}xyz", settings),
                is("abv" + val + "xyzabv" + val + "xyz")
            );
            assertThat(SecurityUtils.replaceEnvVars("abv${env." + k + ":-k182765ggh}xyz", settings), is("abv" + val + "xyz"));
            assertTrue(passwordHasher.check(val.toCharArray(), SecurityUtils.replaceEnvVars("${envbc." + k + "}", settings)));
            checked = true;
        }

        assertTrue(checked);
    }

    @Test
    public void testNoEnvReplace() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_DISABLE_ENVVAR_REPLACEMENT, true).build();
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV}xyz", settings), is("abv${env.MYENV}xyz"));
        assertThat(SecurityUtils.replaceEnvVars("abv${envbc.MYENV}xyz", settings), is("abv${envbc.MYENV}xyz"));
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz", settings), is("abv${env.MYENV:-tTt}xyz"));
        assertThat(
            SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${env.MYENV:-xxx}", settings),
            is("abv${env.MYENV:-tTt}xyz${env.MYENV:-xxx}")
        );
        assertFalse(SecurityUtils.replaceEnvVars("abv${env.MYENV:-tTt}xyz${envbc.MYENV:-xxx}", settings).startsWith("abvtTtxyz$2y$"));
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV:tTt}xyz", settings), is("abv${env.MYENV:tTt}xyz"));
        assertThat(SecurityUtils.replaceEnvVars("abv${env.MYENV-tTt}xyz", settings), is("abv${env.MYENV-tTt}xyz"));
        Map<String, String> env = System.getenv();
        assertTrue(env.size() > 0);

        for (String k : env.keySet()) {
            assertThat(SecurityUtils.replaceEnvVars("abv${env." + k + "}xyz", settings), is("abv${env." + k + "}xyz"));
            assertThat(SecurityUtils.replaceEnvVars("abv${" + k + "}xyz", settings), is("abv${" + k + "}xyz"));
            assertThat(
                SecurityUtils.replaceEnvVars("abv${env." + k + ":-k182765ggh}xyz", settings),
                is("abv${env." + k + ":-k182765ggh}xyz")
            );
            assertThat(
                SecurityUtils.replaceEnvVars("abv${env." + k + "}xyzabv${env." + k + "}xyz", settings),
                is("abv${env." + k + "}xyzabv${env." + k + "}xyz")
            );
            assertThat(
                SecurityUtils.replaceEnvVars("abv${env." + k + ":-k182765ggh}xyz", settings),
                is("abv${env." + k + ":-k182765ggh}xyz")
            );
        }
    }
}
