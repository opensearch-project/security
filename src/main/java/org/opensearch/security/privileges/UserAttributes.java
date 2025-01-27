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

import java.util.Map;
import java.util.Set;

import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;

import org.opensearch.security.user.User;

/**
 * Support for interpolating user attributes used in index patterns and DLS queries.
 *
 * This code was moved over from ConfigModelV7.
 */
public class UserAttributes {
    public static String replaceProperties(String orig, PrivilegesEvaluationContext context) {
        User user = context.getUser();

        orig = orig.replace("${user.name}", user.getName()).replace("${user_name}", user.getName());
        orig = replaceRoles(orig, user);
        orig = replaceSecurityRoles(orig, context);
        for (Map.Entry<String, String> entry : user.getCustomAttributesMap().entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            orig = orig.replace("${" + entry.getKey() + "}", entry.getValue());
            orig = orig.replace("${" + entry.getKey().replace('.', '_') + "}", entry.getValue());
        }
        return orig;
    }

    private static String replaceSecurityRoles(final String orig, PrivilegesEvaluationContext context) {
        String retVal = orig;
        if (orig.contains("${user.securityRoles}") || orig.contains("${user_securityRoles}")) {
            final String commaSeparatedRoles = toQuotedCommaSeparatedString(
                Sets.union(context.getUser().getSecurityRoles(), context.getMappedRoles())
            );
            retVal = orig.replace("${user.securityRoles}", commaSeparatedRoles).replace("${user_securityRoles}", commaSeparatedRoles);
        }
        return retVal;
    }

    @Deprecated
    public static String replaceProperties(String orig, User user) {

        if (user == null || orig == null) {
            return orig;
        }

        orig = orig.replace("${user.name}", user.getName()).replace("${user_name}", user.getName());
        orig = replaceRoles(orig, user);
        orig = replaceSecurityRoles(orig, user);
        for (Map.Entry<String, String> entry : user.getCustomAttributesMap().entrySet()) {
            if (entry == null || entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            orig = orig.replace("${" + entry.getKey() + "}", entry.getValue());
            orig = orig.replace("${" + entry.getKey().replace('.', '_') + "}", entry.getValue());
        }
        return orig;
    }

    private static String replaceRoles(final String orig, final User user) {
        String retVal = orig;
        if (orig.contains("${user.roles}") || orig.contains("${user_roles}")) {
            final String commaSeparatedRoles = toQuotedCommaSeparatedString(user.getRoles());
            retVal = orig.replace("${user.roles}", commaSeparatedRoles).replace("${user_roles}", commaSeparatedRoles);
        }
        return retVal;
    }

    @Deprecated
    private static String replaceSecurityRoles(final String orig, final User user) {
        String retVal = orig;
        if (orig.contains("${user.securityRoles}") || orig.contains("${user_securityRoles}")) {
            final String commaSeparatedRoles = toQuotedCommaSeparatedString(user.getSecurityRoles());
            retVal = orig.replace("${user.securityRoles}", commaSeparatedRoles).replace("${user_securityRoles}", commaSeparatedRoles);
        }
        return retVal;
    }

    private static String toQuotedCommaSeparatedString(final Set<String> roles) {
        return Joiner.on(',').join(Iterables.transform(roles, s -> {
            return new StringBuilder(s.length() + 2).append('"').append(s).append('"').toString();
        }));
    }
}
