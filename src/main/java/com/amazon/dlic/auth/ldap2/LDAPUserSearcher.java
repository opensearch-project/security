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

import org.opensearch.common.settings.Settings;

import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.auth.ldap.util.LdapHelper;
import com.amazon.dlic.auth.ldap.util.Utils;
import org.ldaptive.Connection;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchScope;

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
        Map<String, Settings> userBaseSettingsMap = new HashMap<>(settings.getGroups(ConfigConstants.LDAP_AUTHCZ_USERS));

        if (!userBaseSettingsMap.isEmpty()) {
            if (settings.hasValue(ConfigConstants.LDAP_AUTHC_USERBASE)) {
                throw new RuntimeException(
                    "Both old-style and new-style configuration defined for LDAP authentication backend: " + settings
                );
            }

            return Utils.getOrderedBaseSettings(userBaseSettingsMap);
        } else {
            Settings.Builder settingsBuilder = Settings.builder();
            settingsBuilder.put(ConfigConstants.LDAP_AUTHCZ_BASE, settings.get(ConfigConstants.LDAP_AUTHC_USERBASE, DEFAULT_USERBASE));
            settingsBuilder.put(
                ConfigConstants.LDAP_AUTHCZ_SEARCH,
                settings.get(ConfigConstants.LDAP_AUTHC_USERSEARCH, DEFAULT_USERSEARCH_PATTERN)
            );

            return Collections.singletonList(Pair.of("_legacyConfig", settingsBuilder.build()));
        }
    }

    LdapEntry exists(Connection ldapConnection, String user, final String[] returnAttributes, final boolean shouldFollowReferrals)
        throws Exception {

        if (settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)
            || settings.getAsBoolean(ConfigConstants.LDAP_SEARCH_ALL_BASES, false)
            || settings.hasValue(ConfigConstants.LDAP_AUTHC_USERBASE)) {
            return existsSearchingAllBases(ldapConnection, user, returnAttributes, shouldFollowReferrals);
        } else {
            return existsSearchingUntilFirstHit(ldapConnection, user, returnAttributes, shouldFollowReferrals);
        }

    }

    private LdapEntry existsSearchingUntilFirstHit(
        Connection ldapConnection,
        String user,
        final String[] returnAttributes,
        final boolean shouldFollowReferrals
    ) throws Exception {
        final String username = user;
        final boolean isDebugEnabled = log.isDebugEnabled();
        for (Map.Entry<String, Settings> entry : userBaseSettings) {
            Settings baseSettings = entry.getValue();

            SearchFilter f = new SearchFilter();
            f.setFilter(baseSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_USERSEARCH_PATTERN));
            f.setParameter(ZERO_PLACEHOLDER, username);

            List<LdapEntry> result = LdapHelper.search(
                ldapConnection,
                baseSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_USERBASE),
                f,
                SearchScope.SUBTREE,
                returnAttributes,
                shouldFollowReferrals
            );

            if (isDebugEnabled) {
                log.debug("Results for LDAP search for {} in base {}:\n{}", user, entry.getKey(), result);
            }

            if (result != null && result.size() >= 1) {
                return result.get(0);
            }
        }

        return null;
    }

    private LdapEntry existsSearchingAllBases(
        Connection ldapConnection,
        String user,
        final String[] returnAttributes,
        final boolean shouldFollowReferrals
    ) throws Exception {
        final String username = user;
        Set<LdapEntry> result = new HashSet<>();
        final boolean isDebugEnabled = log.isDebugEnabled();
        for (Map.Entry<String, Settings> entry : userBaseSettings) {
            Settings baseSettings = entry.getValue();

            SearchFilter f = new SearchFilter();
            f.setFilter(baseSettings.get(ConfigConstants.LDAP_AUTHCZ_SEARCH, DEFAULT_USERSEARCH_PATTERN));
            f.setParameter(ZERO_PLACEHOLDER, username);

            List<LdapEntry> foundEntries = LdapHelper.search(
                ldapConnection,
                baseSettings.get(ConfigConstants.LDAP_AUTHCZ_BASE, DEFAULT_USERBASE),
                f,
                SearchScope.SUBTREE,
                returnAttributes,
                shouldFollowReferrals
            );

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
