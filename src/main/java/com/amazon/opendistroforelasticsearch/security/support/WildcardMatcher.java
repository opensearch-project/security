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

package com.amazon.opendistroforelasticsearch.security.support;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Stack;
import java.util.regex.Pattern;

public class WildcardMatcher {

    private static final int NOT_FOUND = -1;

    /**
     * returns true if at least one candidate match at least one pattern (case sensitive)
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAny(final String[] pattern, final String[] candidate) {

        return matchAny(pattern, candidate, false);
    }
    
    public static boolean matchAny(final Collection<String> pattern, final Collection<String> candidate) {

        return matchAny(pattern, candidate, false);
    }

    /**
     * returns true if at least one candidate match at least one pattern
     *
     * @param pattern
     * @param candidate
     * @param ignoreCase
     * @return
     */
    public static boolean matchAny(final String[] pattern, final String[] candidate, boolean ignoreCase) {

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (matchAny(string, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    /**
     * returns true if at least one candidate match at least one pattern
     *
     * @param pattern
     * @param candidate
     * @param ignoreCase
     * @return
     */
    public static boolean matchAny(final Collection<String> pattern, final String[] candidate, boolean ignoreCase) {

        for (String string: pattern) {
            if (matchAny(string, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }
    
    public static boolean matchAny(final Collection<String> pattern, final Collection<String> candidate, boolean ignoreCase) {

        for (String string: pattern) {
            if (matchAny(string, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    /**
     * return true if all candidates find a matching pattern
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAll(final String[] pattern, final String[] candidate) {


        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (!matchAny(pattern, string)) {
                return false;
            }
        }

        return true;
    }

    /**
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean allPatternsMatched(final String[] pattern, final String[] candidate) {

        int matchedPatternNum = 0;

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (matchAny(string, candidate)) {
                matchedPatternNum++;
            }
        }

        return matchedPatternNum == pattern.length && pattern.length > 0;
    }

    public static boolean allPatternsMatched(final Collection<String> pattern, final Collection<String> candidate) {

        int matchedPatternNum = 0;

        for (String string:pattern) {
            if (matchAny(string, candidate)) {
                matchedPatternNum++;
            }
        }

        return matchedPatternNum == pattern.size() && pattern.size() > 0;
    }

    public static boolean matchAny(final String pattern, final String[] candidate) {
        return matchAny(pattern, candidate, false);
    }
    
    public static boolean matchAny(final String pattern, final Collection<String> candidate) {
        return matchAny(pattern, candidate, false);
    }

    /**
     * return true if at least one candidate matches the given pattern
     *
     * @param pattern
     * @param candidate
     * @param ignoreCase
     * @return
     */
    public static boolean matchAny(final String pattern, final String[] candidate, boolean ignoreCase) {

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (match(pattern, string, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    public static boolean matchAny(final String pattern, final Collection<String> candidates, boolean ignoreCase) {

        for (String candidate: candidates) {
            if (match(pattern, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    public static String[] matches(final String pattern, final String[] candidate, boolean ignoreCase) {

        final List<String> ret = new ArrayList<String>(candidate.length);
        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (match(pattern, string, ignoreCase)) {
                ret.add(string);
            }
        }

        return ret.toArray(new String[0]);
    }

    public static List<String> getMatchAny(final String pattern, final String[] candidate) {

        final List<String> matches = new ArrayList<String>(candidate.length);

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (match(pattern, string)) {
                matches.add(string);
            }
        }

        return matches;
    }

    public static List<String> getMatchAny(final String[] patterns, final String[] candidate) {

        final List<String> matches = new ArrayList<String>(candidate.length);

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (matchAny(patterns, string)) {
                matches.add(string);
            }
        }

        return matches;
    }


    public static List<String> getMatchAny(final Collection<String> patterns, final String[] candidate) {

        final List<String> matches = new ArrayList<String>(candidate.length);

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (matchAny(patterns, string)) {
                matches.add(string);
            }
        }

        return matches;
    }

    public static List<String> getMatchAny(final String pattern, final Collection<String> candidate) {

        final List<String> matches = new ArrayList<String>(candidate.size());

        for (final String string: candidate) {
            if (match(pattern, string)) {
                matches.add(string);
            }
        }

        return matches;
    }

    public static List<String> getMatchAny(final String[] patterns, final Collection<String> candidate) {

        final List<String> matches = new ArrayList<String>(candidate.size());

        for (final String string: candidate) {
            if (matchAny(patterns, string)) {
                matches.add(string);
            }
        }

        return matches;
    }
    
    public static Optional<String> getFirstMatchingPattern(final Collection<String> pattern, final String candidate) {

        for (String p : pattern) {
            if (match(p, candidate)) {
                return Optional.of(p);
            }
        }

        return Optional.empty();
    }


    public static List<String> getAllMatchingPatterns(final Collection<String> pattern, final String candidate) {

        final List<String> matches = new ArrayList<String>(pattern.size());

        for (String p : pattern) {
            if (match(p, candidate)) {
                matches.add(p);
            }
        }

        return matches;
    }

    public static List<String> getAllMatchingPatterns(final Collection<String> pattern, final Collection<String> candidates) {

        final List<String> matches = new ArrayList<String>(pattern.size());

        for (String c : candidates) {
            matches.addAll(getAllMatchingPatterns(pattern, c));
        }

        return matches;
    }


    /**
     * returns true if the candidate matches at least one pattern
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAny(final String pattern[], final String candidate) {

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (match(string, candidate)) {
                return true;
            }
        }

        return false;
    }

    /**
     * returns true if the candidate matches at least one pattern
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAny(final Collection<String> pattern, final String candidate) {

        for (String string: pattern) {
            if (match(string, candidate)) {
                return true;
            }
        }

        return false;
    }

    public static boolean match(final String pattern, final String candidate) {
        return match(pattern, candidate, false);
    }

    public static boolean match(String pattern, String candidate, boolean ignoreCase) {

        if (pattern == null || candidate == null) {
            return false;
        }

        if(ignoreCase) {
            pattern = pattern.toLowerCase();
            candidate = candidate.toLowerCase();
        }

        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            // regex
            return Pattern.matches("^"+pattern.substring(1, pattern.length() - 1)+"$", candidate);
        } else if (pattern.length() == 1 && pattern.charAt(0) == '*') {
            return true;
        } else if (pattern.indexOf('?') == NOT_FOUND && pattern.indexOf('*') == NOT_FOUND) {
            return pattern.equals(candidate);
        } else {
            return simpleWildcardMatch(pattern, candidate);
        }
    }

    public static boolean containsWildcard(final String pattern) {
        if (pattern != null
                && (pattern.indexOf("*") > NOT_FOUND || pattern.indexOf("?") > NOT_FOUND || (pattern.startsWith("/") && pattern
                        .endsWith("/")))) {
            return true;
        }

        return false;
    }

    /**
     *
     * @param set will be modified
     * @param stringContainingWc
     * @return
     */
    public static boolean wildcardRemoveFromSet(Set<String> set, String stringContainingWc) {
        if(set == null || set.isEmpty()) {
            return false;
        }
        if(!containsWildcard(stringContainingWc) && set.contains(stringContainingWc)) {
            return set.remove(stringContainingWc);
        } else {
            boolean modified = false;
            Set<String> copy = new HashSet<>(set);

            for(String it: copy) {
                if(WildcardMatcher.match(stringContainingWc, it)) {
                    modified = set.remove(it) || modified;
                }
            }
            return modified;
        }
    }

    /**
     *
     * @param set will be modified
     * @param stringContainingWc
     * @return
     */
    public static boolean wildcardRetainInSet(Set<String> set, String[] setContainingWc) {
        if(set == null || set.isEmpty()) {
            return false;
        }
        boolean modified = false;
        Set<String> copy = new HashSet<>(set);

        for(String it: copy) {
            if(!WildcardMatcher.matchAny(setContainingWc, it)) {
                modified = set.remove(it) || modified;
            }
        }
        return modified;
    }


    //All code below is copied (and slightly modified) from Apache Commons IO

    /*
     * Licensed to the Apache Software Foundation (ASF) under one or more
     * contributor license agreements.  See the NOTICE file distributed with
     * this work for additional information regarding copyright ownership.
     * The ASF licenses this file to You under the Apache License, Version 2.0
     * (the "License"); you may not use this file except in compliance with
     * the License.  You may obtain a copy of the License at
     *
     *      http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software
     * distributed under the License is distributed on an "AS IS" BASIS,
     * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     * See the License for the specific language governing permissions and
     * limitations under the License.
     */


    /**
     * Checks a filename to see if it matches the specified wildcard matcher
     * allowing control over case-sensitivity.
     * <p>
     * The wildcard matcher uses the characters '?' and '*' to represent a
     * single or multiple (zero or more) wildcard characters.
     * N.B. the sequence "*?" does not work properly at present in match strings.
     *
     * @param candidate  the filename to match on
     * @param pattern  the wildcard string to match against
     * @return true if the filename matches the wilcard string
     * @since 1.3
     */
    private static boolean simpleWildcardMatch(final String pattern, final String candidate) {
        if (candidate == null && pattern == null) {
            return true;
        }
        if (candidate == null || pattern == null) {
            return false;
        }

        final String[] wcs = splitOnTokens(pattern);
        boolean anyChars = false;
        int textIdx = 0;
        int wcsIdx = 0;
        final Stack<int[]> backtrack = new Stack<>();

        // loop around a backtrack stack, to handle complex * matching
        do {
            if (backtrack.size() > 0) {
                final int[] array = backtrack.pop();
                wcsIdx = array[0];
                textIdx = array[1];
                anyChars = true;
            }

            // loop whilst tokens and text left to process
            while (wcsIdx < wcs.length) {

                if (wcs[wcsIdx].equals("?")) {
                    // ? so move to next text char
                    textIdx++;
                    if (textIdx > candidate.length()) {
                        break;
                    }
                    anyChars = false;

                } else if (wcs[wcsIdx].equals("*")) {
                    // set any chars status
                    anyChars = true;
                    if (wcsIdx == wcs.length - 1) {
                        textIdx = candidate.length();
                    }

                } else {
                    // matching text token
                    if (anyChars) {
                        // any chars then try to locate text token
                        textIdx = checkIndexOf(candidate, textIdx, wcs[wcsIdx]);
                        if (textIdx == NOT_FOUND) {
                            // token not found
                            break;
                        }
                        final int repeat = checkIndexOf(candidate, textIdx + 1, wcs[wcsIdx]);
                        if (repeat >= 0) {
                            backtrack.push(new int[] {wcsIdx, repeat});
                        }
                    } else {
                        // matching from current position
                        if (!checkRegionMatches(candidate, textIdx, wcs[wcsIdx])) {
                            // couldnt match token
                            break;
                        }
                    }

                    // matched text token, move text index to end of matched token
                    textIdx += wcs[wcsIdx].length();
                    anyChars = false;
                }

                wcsIdx++;
            }

            // full match
            if (wcsIdx == wcs.length && textIdx == candidate.length()) {
                return true;
            }

        } while (backtrack.size() > 0);

        return false;
    }

    /**
     * Splits a string into a number of tokens.
     * The text is split by '?' and '*'.
     * Where multiple '*' occur consecutively they are collapsed into a single '*'.
     *
     * @param text  the text to split
     * @return the array of tokens, never null
     */
    private static String[] splitOnTokens(final String text) {
        // used by wildcardMatch
        // package level so a unit test may run on this

        if (text.indexOf('?') == NOT_FOUND && text.indexOf('*') == NOT_FOUND) {
            return new String[] { text };
        }

        final char[] array = text.toCharArray();
        final ArrayList<String> list = new ArrayList<>();
        final StringBuilder buffer = new StringBuilder();
        char prevChar = 0;
        for (final char ch : array) {
            if (ch == '?' || ch == '*') {
                if (buffer.length() != 0) {
                    list.add(buffer.toString());
                    buffer.setLength(0);
                }
                if (ch == '?') {
                    list.add("?");
                } else if (prevChar != '*') {// ch == '*' here; check if previous char was '*'
                    list.add("*");
                }
            } else {
                buffer.append(ch);
            }
            prevChar = ch;
        }
        if (buffer.length() != 0) {
            list.add(buffer.toString());
        }

        return list.toArray( new String[ list.size() ] );
    }

    /**
     * Checks if one string contains another starting at a specific index using the
     * case-sensitivity rule.
     * <p>
     * This method mimics parts of {@link String#indexOf(String, int)}
     * but takes case-sensitivity into account.
     *
     * @param str  the string to check, not null
     * @param strStartIndex  the index to start at in str
     * @param search  the start to search for, not null
     * @return the first index of the search String,
     *  -1 if no match or {@code null} string input
     * @throws NullPointerException if either string is null
     * @since 2.0
     */
    private static int checkIndexOf(final String str, final int strStartIndex, final String search) {
        final int endIndex = str.length() - search.length();
        if (endIndex >= strStartIndex) {
            for (int i = strStartIndex; i <= endIndex; i++) {
                if (checkRegionMatches(str, i, search)) {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * Checks if one string contains another at a specific index using the case-sensitivity rule.
     * <p>
     * This method mimics parts of {@link String#regionMatches(boolean, int, String, int, int)}
     * but takes case-sensitivity into account.
     *
     * @param str  the string to check, not null
     * @param strStartIndex  the index to start at in str
     * @param search  the start to search for, not null
     * @return true if equal using the case rules
     * @throws NullPointerException if either string is null
     */
    private static boolean checkRegionMatches(final String str, final int strStartIndex, final String search) {
        return str.regionMatches(false, strStartIndex, search, 0, search.length());
    }
}
