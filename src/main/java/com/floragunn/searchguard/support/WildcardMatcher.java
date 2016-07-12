/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.support;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class WildcardMatcher {

    public static boolean matchAny(final String[] pattern, final String[] candidate) {

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (matchAny(string, candidate)) {
                return true;
            }
        }

        return false;
    }

    public static boolean matchAll(final String[] pattern, final String[] candidate) {

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (!matchAny(pattern, string)) {
                return false;
            }
        }

        return true;
    }

    public static boolean matchAny(final String pattern, final String[] candidate) {

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (match(pattern, string)) {
                return true;
            }
        }

        return false;
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

    public static boolean matchAny(final String pattern[], final String candidate) {

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (match(string, candidate)) {
                return true;
            }
        }

        return false;
    }

    public static boolean match(final String pattern, final String candidate) {

        if (pattern == null || candidate == null) {
            return false;
        }

        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            // regex
            return Pattern.matches("^"+pattern.substring(1, pattern.length() - 1)+"$", candidate);
        }

        if (!pattern.startsWith("/") && !pattern.endsWith("/")) {
            // simple
            return Pattern.matches(pattern.replace(".", "\\.").replace("*", ".*").replace("?", "."), candidate);
        }

        return false; // TODO throw exception
    }

    public static boolean containsWildcard(final String pattern) {
        if (pattern != null && (pattern.contains("*") || pattern.contains("?") 
                || (pattern.startsWith("/") && pattern.endsWith("/")))) {
            return true;
        }

        return false;
    }

}
