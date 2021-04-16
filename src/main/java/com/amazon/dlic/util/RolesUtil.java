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
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RolesUtil {
    private static final Logger log = LogManager.getLogger(RolesUtil.class);

    /*
     * Split the given rolesObject to one or several roles
     * We accept String or JSONarray only
     *
     * rolesObject should be String if given by roles_key
     * rolesObject should be String or ArrayList if given by roles_path
     *
     * Here are some examples:
     *
     *   JWT paylaoad contains:
     *     "access": {
     *       "roles": [
     *         "readall, testrole",
     *         "admin",
     *         123,
     *         "kibanauser"
     *       ]
     *     }
     *  if contains a Json array, it should return elements that is a String.
     *    roles_path = $["access"]["roles"]
     *    should return ["readall, testrole", "admin", "kibanauser"]
     *
     *  if contains a String, it will split by comma to get roles.
     *    roles_path = $["access"]["roles"][0]
     *    should return ["readall", "testrole"]
     *
     *  if contains neither Json array nor String, e.g. Json Object, it should throw exception.
     *    roles_path = $["access"]
     *    should throw ElasticsearchSecurityException
     */
    public static String[] split(Object rolesObject) {
        if (rolesObject == null) {
            return new String[0];
        } else if (rolesObject instanceof ArrayList) {
            ArrayList<String> rolesList = (ArrayList<String>) ((ArrayList)rolesObject).stream().filter(x -> x instanceof String).collect(Collectors.toList());
            return rolesList.toArray(new String[rolesList.size()]);
        } else if (rolesObject instanceof String) {
            return splitString(String.valueOf(rolesObject));
        }
        throw new IllegalArgumentException("Expected type String or JSON array in the JWT for roles_key/roles_path");
    }
    public static String[] splitString(String string) {
        String[] result = string.split(",");

        for (int i = 0; i < result.length; i++) {
            result[i] = result[i].trim();
        }

        return result;
    }

}
