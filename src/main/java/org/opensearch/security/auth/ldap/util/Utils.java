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

package org.opensearch.security.auth.ldap.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;

import org.ldaptive.LdapAttribute;

public final class Utils {

    private static final Logger log = LogManager.getLogger(Utils.class);

    private Utils() {

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
                int attributeOrder = Integer.compare(
                    o1.getValue().getAsInt("order", Integer.MAX_VALUE),
                    o2.getValue().getAsInt("order", Integer.MAX_VALUE)
                );

                if (attributeOrder != 0) {
                    return attributeOrder;
                }

                return o1.getKey().compareTo(o2.getKey());
            }
        });
    }

    public static String getSingleStringValue(LdapAttribute attribute) {
        if (attribute == null) {
            return null;
        }

        if (attribute.size() > 1) {
            if (log.isDebugEnabled()) {
                log.debug("Multiple values found for {} ({})", attribute.getName(), attribute);
            }
        }

        return attribute.getStringValue();
    }
}
