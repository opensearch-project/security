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

package org.opensearch.security.support;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class WildcardMatcherTest {
    boolean ignoreCase;

    @Test
    public void any() {
        WildcardMatcher subject = applyCase(WildcardMatcher.ANY);
        assertTrue(subject.test("any_string"));
        assertTrue(subject.test(""));
        assertTrue(subject.matchAny("any_string"));
        assertTrue(subject.matchAny(Arrays.asList("any_string")));
        assertTrue(subject.matchAny(Stream.of("any_string")));
        assertEquals("*", subject.toString());
    }

    @Test
    public void none() {
        WildcardMatcher subject = applyCase(WildcardMatcher.NONE);
        assertFalse(subject.test("any_string"));
        assertFalse(subject.test(""));
        assertFalse(subject.matchAny("any_string"));
        assertFalse(subject.matchAny(Arrays.asList("any_string")));
        assertFalse(subject.matchAny(Stream.of("any_string")));
        assertEquals("<NONE>", subject.toString());
    }

    @Test
    public void anyFromStar() {
        assertSame(WildcardMatcher.ANY, applyCase(WildcardMatcher.from("*")));
    }

    @Test
    public void noneFromNull() {
        assertSame(WildcardMatcher.NONE, applyCase(WildcardMatcher.from()));
        assertSame(WildcardMatcher.NONE, applyCase(WildcardMatcher.from((String) null)));
    }

    @Test
    public void exact() {
        String base = "exact_string";
        WildcardMatcher subject = applyCase(WildcardMatcher.from(base));
        assertTrue(subject instanceof WildcardMatcher.Exact);
        assertTrue(subject.test(base));
        assertFalse(subject.test(base + "_x"));
        assertEquals(ignoreCase, subject.test(base.toUpperCase()));
        assertTrue(subject.matchAny(base));
        assertTrue(subject.matchAny(base, "foo"));
        assertFalse(subject.matchAny("foo"));
        assertTrue(subject.matchAny(Arrays.asList(base, "foo")));
        assertFalse(subject.matchAny(Arrays.asList("foo")));
        assertEquals(base, subject.toString());
        assertEquals(applyCase(WildcardMatcher.from(base)), subject);
        assertNotEquals(applyCase(WildcardMatcher.from(base + "x")), subject);
        assertNotEquals(applyCase(WildcardMatcher.from(base + "*")), subject);
        assertEquals(Arrays.asList(base), subject.getMatchAny(Arrays.asList(base, "other"), Collectors.toList()));
    }

    @Test
    public void prefix() {
        String base = "prefix_string";
        WildcardMatcher subject = applyCase(WildcardMatcher.from(base + "*"));
        assertTrue(subject instanceof WildcardMatcher.PrefixMatcher);
        assertTrue(subject.test(base + "_more"));
        assertTrue(subject.test(base));
        assertFalse(subject.test(base.substring(0, 5)));
        assertFalse(subject.test("more_" + base));
        assertEquals(ignoreCase, subject.test(base.toUpperCase()));
        assertEquals(ignoreCase, subject.test(base.toUpperCase() + "_more"));
        assertTrue(subject.matchAny(base));
        assertTrue(subject.matchAny(base, "foo"));
        assertFalse(subject.matchAny("foo"));
        assertEquals(base + "*", subject.toString());
        assertEquals(applyCase(WildcardMatcher.from(subject.toString())), subject);
        assertNotEquals(applyCase(WildcardMatcher.from(subject.toString() + "x")), subject);
        assertEquals(
            Arrays.asList(base, base + "_more"),
            subject.getMatchAny(Arrays.asList(base, base + "_more", "other"), Collectors.toList())
        );
        assertEquals(
            Arrays.asList(base, base + "_more"),
            StreamSupport.stream(subject.iterateMatching(Arrays.asList(base, base + "_more", "other")).spliterator(), false).toList()
        );
        assertEquals(Arrays.asList(base, base + "_more"), subject.matching(Arrays.asList(base, base + "_more", "other")));
    }

    @Test
    public void contains() {
        String base = "contains_string";
        WildcardMatcher subject = applyCase(WildcardMatcher.from("*" + base + "*"));
        assertTrue(subject instanceof WildcardMatcher.ContainsMatcher);
        assertTrue(subject.test(base));
        assertTrue(subject.test(base + "_a"));
        assertTrue(subject.test("a_" + base));
        assertTrue(subject.test("a_" + base + "_a"));
        assertFalse(subject.test("string".substring(0, 5)));
        assertEquals(ignoreCase, subject.test(base.toUpperCase()));
        assertEquals(ignoreCase, subject.test("a_" + base.toUpperCase() + "_a"));
        assertEquals("*" + base + "*", subject.toString());
        assertEquals(applyCase(WildcardMatcher.from(subject.toString())), subject);
        assertNotEquals(applyCase(WildcardMatcher.from(subject.toString() + "x")), subject);
    }

    @Test
    public void simple() {
        String base1 = "my";
        String base2 = "string";
        WildcardMatcher subject = applyCase(WildcardMatcher.from(base1 + "*" + base2 + "*"));
        assertTrue(subject instanceof WildcardMatcher.SimpleMatcher);
        assertTrue(subject.test(base1 + base2));
        assertTrue(subject.test(base1 + "_x_" + base2));
        assertTrue(subject.test(base1 + "_x_" + base2 + "_y"));
        assertFalse(subject.test("x_" + base1 + base2));
        assertEquals(ignoreCase, subject.test(base1 + base2.toUpperCase()));
    }

    @Test
    public void simple_withQuestionMark() {
        String base = "string";
        WildcardMatcher subject = applyCase(WildcardMatcher.from("?" + base));
        assertTrue(subject instanceof WildcardMatcher.SimpleMatcher);
        assertFalse(subject.test(base));
        assertTrue(subject.test("." + base));
        assertFalse(subject.test(".." + base));
        assertFalse(subject.test("." + base + "."));
        assertEquals(ignoreCase, subject.test("." + base.toUpperCase()));
    }

    @Test
    public void simple_withQuestionMarkAndStar() {
        String base1 = "my";
        String base2 = "string";
        WildcardMatcher subject = applyCase(WildcardMatcher.from(base1 + "?" + base2 + "*"));
        assertTrue(subject instanceof WildcardMatcher.SimpleMatcher);
        assertFalse(subject.test(base1 + base2));
        assertTrue(subject.test(base1 + "_" + base2));
        assertTrue(subject.test(base1 + "_" + base2 + "_y"));
        assertFalse(subject.test("x_" + base1 + base2));
        assertEquals(ignoreCase, subject.test(base1 + "_" + base2.toUpperCase()));
    }

    @Test
    public void simple_questionMark() {
        WildcardMatcher subject = applyCase(WildcardMatcher.from("?"));
        assertTrue(subject instanceof WildcardMatcher.SimpleMatcher);
        assertFalse(subject.test(""));
        assertTrue(subject.test("."));
        assertFalse(subject.test(".."));
    }

    @Test
    public void regex() {
        String base1 = "my";
        String base2 = "string";
        WildcardMatcher subject = applyCase(WildcardMatcher.from("/" + base1 + ".*" + base2 + "./"));
        assertTrue(subject instanceof WildcardMatcher.RegexMatcher);
        assertFalse(subject.test(base1 + base2));
        assertTrue(subject.test(base1 + base2 + "x"));
        assertTrue(subject.test(base1 + "_x_" + base2 + "x"));
        assertFalse(subject.test("x_" + base1 + base2 + "x"));
        assertEquals(ignoreCase, subject.test(base1 + base2.toUpperCase() + "x"));
        assertEquals("/" + base1 + ".*" + base2 + "./", subject.toString());
        assertEquals(applyCase(WildcardMatcher.from(subject.toString())), subject);
        assertNotEquals(applyCase(WildcardMatcher.from(subject.toString() + "x")), subject);
    }

    @Test
    public void combined() {
        String base1 = "string";
        String base2 = "other";
        WildcardMatcher subject = applyCase(WildcardMatcher.from(base1 + "*", base2));
        assertTrue(subject instanceof WildcardMatcher.MatcherCombiner);
        assertTrue(subject.test(base1 + "_more"));
        assertTrue(subject.test(base1));
        assertTrue(subject.test(base2));
        assertFalse(subject.test(base2 + "_more"));
        assertEquals(ignoreCase, subject.test(base1.toUpperCase()));
        assertEquals(ignoreCase, subject.test(base1.toUpperCase() + "_more"));
        assertEquals(ignoreCase, subject.test(base2.toUpperCase()));
        assertEquals("[" + base1 + "*, " + base2 + "]", subject.toString());
        assertEquals(applyCase(WildcardMatcher.from(base1 + "*", base2)), subject);
        assertNotEquals(applyCase(WildcardMatcher.from(base1 + "*", base2, "x")), subject);
        assertNotEquals(applyCase(WildcardMatcher.from(base1 + "*")), subject);
    }

    @Test
    public void concat() {
        String base1 = "string";
        String base2 = "other";
        WildcardMatcher subject1 = applyCase(WildcardMatcher.from(base1 + "*"));
        assertSame(subject1, subject1.concat(Collections.emptyList()));
        WildcardMatcher subject2 = subject1.concat(Collections.singleton(applyCase(WildcardMatcher.from(base2))));
        assertTrue(subject2 instanceof WildcardMatcher.MatcherCombiner);
        assertTrue(subject2.test(base1));
        assertTrue(subject2.test(base2));
        assertFalse(subject2.test(base2 + "_more"));
    }

    public WildcardMatcherTest(boolean ignoreCase) {
        this.ignoreCase = ignoreCase;
    }

    @Parameterized.Parameters(name = "ignoreCase: {0}")
    public static Collection<Object[]> params() {
        return Arrays.asList(new Object[] { false }, new Object[] { true });
    }

    private WildcardMatcher applyCase(WildcardMatcher wildcardMatcher) {
        if (ignoreCase) {
            return wildcardMatcher.ignoreCase();
        } else {
            return wildcardMatcher;
        }
    }
}
