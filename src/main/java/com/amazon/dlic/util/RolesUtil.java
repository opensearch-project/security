/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.amazon.dlic.util;

import java.util.List;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RolesUtil {
    private static final Logger log = LogManager.getLogger(RolesUtil.class);
    private static final Pattern pattern = Pattern.compile("\\s*,\\s*");
    private static final String[] EMPTY_STRING_ARRAY = new String[0];

    /*
     * Split the given roles to one or several roles
     * We accept String or JSON array only, other types will be ignored and will issue a warning
     *
     *
     * Here are some examples:
     *
     *   JWT payload contains:
     *     "access": {
     *       "roles": [
     *         "readall, testrole",
     *         "admin",
     *         123,
     *         "kibanauser"
     *       ]
     *     }
     *  if the path contains a Json array, it should return elements that is a String.
     *    roles_path = $["access"]["roles"]
     *    should return ["readall, testrole", "admin", "kibanauser"]
     *
     *  if the path contains a String, it will split by comma to get roles.
     *    roles_path = $["access"]["roles"][0]
     *    should return ["readall", "testrole"]
     *
     *  if the path contains neither Json array nor String, e.g. Json Object, it should throw exception.
     *    roles_path = $["access"]
     *    should throw IllegalArgumentException
     */
    public static String[] split(Object roles) {
        if (roles == null) {
            return EMPTY_STRING_ARRAY;
        } else if (roles instanceof List) {
            String[] filteredRoles = (String[]) ((List)roles)
                    .stream()
                    .filter(x -> {
                        if (!(x instanceof String)){
                            log.warn("We only accept String for elements in JSON array, {} is not a String", x);
                            return false;
                        } else {
                            return true;
                        }
                    })
                    .toArray(String[]::new);
            return filteredRoles;
        } else if (roles instanceof String) {
            return splitString(String.valueOf(roles));
        }
        throw new IllegalArgumentException("Expected type String or JSON array in the JWT for roles_key/roles_path");
    }
    public static String[] splitString(String role) {
        String[] result = pattern.split(role);

        for (int i = 0; i < result.length; i++) {
            result[i] = result[i].trim();
        }

        return result;
    }

}
