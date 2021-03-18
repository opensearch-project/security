/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.dlic.auth.ldap2;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.ldaptive.Connection;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchScope;

import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.auth.ldap.util.LdapHelper;
import com.amazon.dlic.auth.ldap.util.Utils;

public class LDAPUserSearcher {
    protected static final Logger log = LogManager.getLogger(LDAPUserSearcher.class);

    private static final int ZERO_PLACEHOLDER = 0;
    private static final String DEFAULT_USERBASE = "";
    private static final String DEFAULT_USERSEARCH_PATTERN = "(sAMAccountName={0})";

    private final Settings settings;
    private final List<Map.Entry<String, Settings>> userBaseSettings;

    public LDAPUserSearcher(Settings settings) {
        this.settings = settings;
        this.userBaseSettings = getUserBaseSettings(settings);
    }

    static List<Map.Entry<String, Settings>> getUserBaseSettings(Settings settings) {
        Map<String, Settings> userBaseSettingsMap = new HashMap<>(
                settings.getGroups(ConfigConstants.LDAP_AUTHCZ_USERS));

        if (!userBaseSettingsMap.isEmpty()) {
            if (settings.hasValue(ConfigConstants.LDAP_AUTHC_USERBASE)) {
                throw new RuntimeException(
                        "Both old-style and new-style configuration defined for LDAP authentication backend: "
                                + settings);
            }

            return Utils.getOrderedBaseSettings(userBaseSettingsMap);
        } else {
            Settings.Builder settingsBuilder = Settings.builder();
            settingsBuilder.put(ConfigConstants.LDAP_AUTHCZ_BASE,
                    settings.get(ConfigConstants.LDAP_AUTHC_USERBASE, DEFAULT_USERBASE));
            settingsBuilder.put(ConfigConstants.LDAP_AUTHCZ_SEARCH,
                    settings.get(ConfigConstants.LDAP_AUTHC_USERSEARCH, DEFAULT_USERSEARCH_PATTERN));

            return Collections.singletonList(Pair.of("_legacyConfig", settingsBuilder.build()));
        }
    }

    LdapEntry exists(Connection ldapConnection, String user) throws Exception {

        if (settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)
                || settings.getAsBoolean(ConfigConstants.LDAP_SEARCH_ALL_BASES, false)
                || settings.hasValue(ConfigConstants.LDAP_AUTHC_USERBASE)) {
            return existsSearchingAllBases(ldapConnection, user);
        } else {
            return existsSearchingUntilFirstHit(ldapConnection, user);
        }

    }

    private LdapEntry existsSearchingUntilFirstHit(Connection ldapConnection, String user) throws Exception {
        final String username = user;
        final boolean isDebugEnabled = log.isDebugEnabled();
        for (Map.Entry<String, Settings> entry : userBaseSettings) {
            Settings baseSettings = entry.getValue();

            SearchFilter f = new SearchFilter();
            f.setFilter(baseSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_USERSEARCH_PATTERN));
            f.setParameter(ZERO_PLACEHOLDER, username);

            List<LdapEntry> result = LdapHelper.search(ldapConnection,
                    baseSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_USERBASE),
                    f,
                    SearchScope.SUBTREE);

            if (isDebugEnabled) {
                log.debug("Results for LDAP search for {} in base {}:\n{}", user, entry.getKey(), result);
            }

            if (result != null && result.size() >= 1) {
                return result.get(0);
            }
        }

        return null;
    }

    private LdapEntry existsSearchingAllBases(Connection ldapConnection, String user) throws Exception {
        final String username = user;
        Set<LdapEntry> result = new HashSet<>();
        final boolean isDebugEnabled = log.isDebugEnabled();
        for (Map.Entry<String, Settings> entry : userBaseSettings) {
            Settings baseSettings = entry.getValue();

            SearchFilter f = new SearchFilter();
            f.setFilter(baseSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_USERSEARCH_PATTERN));
            f.setParameter(ZERO_PLACEHOLDER, username);

            List<LdapEntry> foundEntries = LdapHelper.search(ldapConnection,
                    baseSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_USERBASE),
                    f,
                    SearchScope.SUBTREE);

            if (isDebugEnabled) {
                log.debug("Results for LDAP search for {} in base {}:\n{}", user, entry.getKey(), result);
            }

            if (foundEntries != null) {
                result.addAll(foundEntries);
            }
        }

        if (result.isEmpty()) {
            log.debug("No user {} found", username);
            return null;
        }

        if (result.size() > 1) {
            log.debug("More than one user for '{}' found", username);
            return null;
        }

        return result.iterator().next();
    }

}
