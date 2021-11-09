/*
 * Copyright OpenSearch Contributors
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

package com.amazon.dlic.auth.ldap.util;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;
import org.ldaptive.Connection;
import org.ldaptive.LdapAttribute;

public final class Utils {

    private static final Logger log = LogManager.getLogger(Utils.class);

    private Utils() {

    }

    public static void unbindAndCloseSilently(final Connection connection) {
        if (connection == null) {
            return;
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    connection.close();
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            // ignore
        }
    }

    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Settings settings) {
        return getOrderedBaseSettings(settings.getAsGroups());
    }

    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Map<String, Settings> settingsMap) {
        return getOrderedBaseSettings(settingsMap.entrySet());
    }

    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Set<Map.Entry<String, Settings>> set) {
        List<Map.Entry<String, Settings>> result = new ArrayList<>(set);

        sortBaseSettings(result);

        return Collections.unmodifiableList(result);
    }

    private static void sortBaseSettings(List<Map.Entry<String, Settings>> list) {
        list.sort(new Comparator<Map.Entry<String, Settings>>() {

            @Override
            public int compare(Map.Entry<String, Settings> o1, Map.Entry<String, Settings> o2) {
                int attributeOrder = Integer.compare(o1.getValue().getAsInt("order", Integer.MAX_VALUE),
                        o2.getValue().getAsInt("order", Integer.MAX_VALUE));

                if (attributeOrder != 0) {
                    return attributeOrder;
                }

                return o1.getKey().compareTo(o2.getKey());
            }
        });
    }

    public static String getSingleStringValue(LdapAttribute attribute) {
        if(attribute == null) {
            return null;
        }

        if(attribute.size() > 1) {
            if(log.isDebugEnabled()) {
                log.debug("Multiple values found for {} ({})", attribute.getName(), attribute);
            }
        }

        return attribute.getStringValue();
    }
}
