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
package org.opensearch.security.privileges;

import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;
import org.apache.commons.text.StringSubstitutor;

/**
 * Support for interpolating user attributes used in index patterns and DLS queries.
 *
 * This code was moved over from ConfigModelV7.
 */
public class UserAttributes {
    private static final Pattern UNRESOLVED_ATTRIBUTE_PATTERN = Pattern.compile("\\$\\{([^}]+)\\}");

    public static boolean needsAttributeSubstitution(String patternString) {
        return patternString.contains("${");
    }

    /**
     * Returns the names of all unresolved ${...} attribute references remaining
     * in {@code s} after substitution has been performed.
     */
    public static List<String> findUnresolvedAttributes(String s) {
        return UNRESOLVED_ATTRIBUTE_PATTERN.matcher(s).results().map(m -> m.group(1)).toList();
    }

    public static String replaceProperties(String orig, PrivilegesEvaluationContext context) {
        final var user = context.getUser();

        final var replacementsWithDots = new HashMap<String, String>();
        replacementsWithDots.put("user.name", user.getName());
        replacementsWithDots.put("user.roles", toQuotedCommaSeparatedString(user.getRoles()));
        replacementsWithDots.put(
            "user.securityRoles",
            toQuotedCommaSeparatedString(Sets.union(context.getUser().getSecurityRoles(), context.getMappedRoles()))
        );
        replacementsWithDots.putAll(user.getCustomAttributesMap());

        // we also support referencing variables with underscores instead of dots => we need both in our lookup table.
        final var replacements = new HashMap<>(replacementsWithDots);
        replacementsWithDots.forEach((k, v) -> replacements.put(k.replace(".", "_"), v));

        final var stringSubstitutor = new StringSubstitutor(replacements).setEnableSubstitutionInVariables(true);
        orig = stringSubstitutor.replace(orig);
        return orig;
    }

    private static String toQuotedCommaSeparatedString(final Set<String> roles) {
        return Joiner.on(',').join(Iterables.transform(roles, s -> {
            return new StringBuilder(s.length() + 2).append('"').append(s).append('"').toString();
        }));
    }
}
