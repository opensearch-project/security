/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RolesUtil {
    private static final Logger log = LogManager.getLogger(RolesUtil.class);

    /*
     * Split the given rolesObject to one or several roles
     * rolesObject should be a String if given by roles_key
     * rolesObject should always be net.minidev.json.JSONArray if given by roles_path (jayway config set to ALWAYS_RETURN_LIST)
     *
     * Here are some examples:
     *
     *   JWT paylaoad contains:
     *     "access": {
     *       "roles": [
     *         "readall, testrole",
     *         "admin",
     *         "kibanauser"
     *       ]
     *     }
     *  if contains a Json array, it will convert all elements to String and split by comma to get roles.
     *    roles_path = $["access"]["roles"]
     *    the result should be ("readall", "testrole", "admin", "kibanauser")
     *  if contains a String, it will split by comma to get roles.
     *    roles_path = $["access"]["roles"][0]
     *    the result should be ("readall", "testrole")
     *  if contains neither Json array nor String, e.g. Json Object, it will convert the value to String and split by comma to get roles
     *    roles_path = $["access"]
     *    the result should be ("{roles=[readall", "testrole", "admin", "kinanauser]}")
     */
    public static String[] split(Object rolesObject) {
        if (rolesObject == null) {
            return new String[0];
        } else if (rolesObject instanceof Collection) {
            List<String> roles = new ArrayList<>();
            for (Object object : (Collection<?>) rolesObject) {
                if (object instanceof Collection) {
                    for (Object subObject : (Collection<?>) object) {
                        roles.addAll(Arrays.asList(splitString(String.valueOf(subObject))));
                    }
                } else {
                    if (!(object instanceof String)) {
                        // We expect a String or Collection. If we find something else, convert to
                        // String but issue a warning
                        log.warn(
                                "Expected type String or Collection for roles in the JWT for roles_key {}, but value was '{}' ({}). Will convert this value to String.",
                                object, object.getClass());
                    }
                    roles.addAll(Arrays.asList(splitString(String.valueOf(object))));
                }
            }

            return roles.toArray(new String[roles.size()]);
        } else {
            if (!(rolesObject instanceof String)) {
                // We expect a String or Collection. If we find something else, convert to
                // String but issue a warning
                log.warn(
                        "Expected type String or Collection for roles in the JWT for roles_key {}, but value was '{}' ({}). Will convert this value to String.",
                        rolesObject, rolesObject.getClass());
            }

            return splitString(String.valueOf(rolesObject));
        }
    }

    public static String[] splitString(String string) {
        String[] result = string.split(",");

        for (int i = 0; i < result.length; i++) {
            result[i] = result[i].trim();
        }

        return result;
    }

}
