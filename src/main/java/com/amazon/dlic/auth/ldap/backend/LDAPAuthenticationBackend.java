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

package com.amazon.dlic.auth.ldap.backend;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;

import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchScope;

import com.amazon.dlic.auth.ldap.LdapUser;
import com.amazon.dlic.auth.ldap.util.ConfigConstants;
import com.amazon.dlic.auth.ldap.util.LdapHelper;
import com.amazon.dlic.auth.ldap.util.Utils;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.support.WildcardMatcher;

public class LDAPAuthenticationBackend implements AuthenticationBackend {

    static final int ZERO_PLACEHOLDER = 0;
    static final String DEFAULT_USERBASE = "";
    static final String DEFAULT_USERSEARCH_PATTERN = "(sAMAccountName={0})";

    protected static final Logger log = LogManager.getLogger(LDAPAuthenticationBackend.class);

    private final Settings settings;
    private final Path configPath;
    private final List<Map.Entry<String, Settings>> userBaseSettings;
    private final int customAttrMaxValueLen;
    private final WildcardMatcher whitelistedCustomLdapAttrMatcher;

    public LDAPAuthenticationBackend(final Settings settings, final Path configPath) {
        this.settings = settings;
        this.configPath = configPath;
        this.userBaseSettings = getUserBaseSettings(settings);

        customAttrMaxValueLen = settings.getAsInt(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 36);
        whitelistedCustomLdapAttrMatcher = WildcardMatcher.from(settings.getAsList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST,
                Collections.singletonList("*")));
    }

    @Override
    public User authenticate(final AuthCredentials credentials) throws OpenSearchSecurityException {

        Connection ldapConnection = null;
        final String user =credentials.getUsername();
        byte[] password = credentials.getPassword();

        try {
            LdapEntry entry;
            String dn;
            ConnectionConfig connectionConfig;

            try {
                ldapConnection = LDAPAuthorizationBackend.getConnection(settings, configPath);

                entry = exists(user, ldapConnection, settings, userBaseSettings);

                // fake a user that no exists
                // makes guessing if a user exists or not harder when looking on the
                // authentication delay time
                if (entry == null && settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)) {
                    String fakeLognDn = settings.get(ConfigConstants.LDAP_FAKE_LOGIN_DN,
                            "CN=faketomakebindfail,DC=" + UUID.randomUUID().toString());
                    entry = new LdapEntry(fakeLognDn);
                    password = settings.get(ConfigConstants.LDAP_FAKE_LOGIN_PASSWORD, "fakeLoginPwd123")
                            .getBytes(StandardCharsets.UTF_8);
                } else if (entry == null) {
                    throw new OpenSearchSecurityException("No user " + user + " found");
                }

                dn = entry.getDn();

                if (log.isTraceEnabled()) {
                    log.trace("Try to authenticate dn {}", dn);
                }

                connectionConfig = ldapConnection.getConnectionConfig();
            } finally {
                Utils.unbindAndCloseSilently(ldapConnection);
            }

            LDAPAuthorizationBackend.checkConnection(connectionConfig, dn, password);

            final String usernameAttribute = settings.get(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, null);
            String username = dn;

            if (usernameAttribute != null && entry.getAttribute(usernameAttribute) != null) {
                username = Utils.getSingleStringValue(entry.getAttribute(usernameAttribute));
            }

            if (log.isDebugEnabled()) {
                log.debug("Authenticated username {}", username);
            }

            // by default all ldap attributes which are not binary and with a max value
            // length of 36 are included in the user object
            // if the whitelist contains at least one value then all attributes will be
            // additional check if whitelisted (whitelist can contain wildcard and regex)
            return new LdapUser(username, user, entry, credentials, customAttrMaxValueLen, whitelistedCustomLdapAttrMatcher);

        } catch (final Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to authenticate user due to ", e);
            }
            throw new OpenSearchSecurityException(e.toString(), e);
        } finally {
            Arrays.fill(password, (byte) '\0');
            password = null;
            Utils.unbindAndCloseSilently(ldapConnection);
        }

    }

    @Override
    public String getType() {
        return "ldap";
    }

    @Override
    public boolean exists(final User user) {
        Connection ldapConnection = null;
        String userName = user.getName();

        if (user instanceof LdapUser) {
            userName = ((LdapUser) user).getUserEntry().getDn();
        }

        try {
            ldapConnection = LDAPAuthorizationBackend.getConnection(settings, configPath);
            LdapEntry userEntry = exists(userName, ldapConnection, settings, userBaseSettings);
            boolean exists = userEntry != null;
            
            if(exists) {
                user.addAttributes(LdapUser.extractLdapAttributes(userName, userEntry, customAttrMaxValueLen, whitelistedCustomLdapAttrMatcher));
            }
            
            return exists;
            
        } catch (final Exception e) {
            log.warn("User {} does not exist due to ", userName, e);
            return false;
        } finally {
            Utils.unbindAndCloseSilently(ldapConnection);
        }
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

    static LdapEntry exists(final String user, Connection ldapConnection, Settings settings,
            List<Map.Entry<String, Settings>> userBaseSettings) throws Exception {

        if (settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)
                || settings.getAsBoolean(ConfigConstants.LDAP_SEARCH_ALL_BASES, false)
                || settings.hasValue(ConfigConstants.LDAP_AUTHC_USERBASE)) {
            return existsSearchingAllBases(user, ldapConnection, userBaseSettings);
        } else {
            return existsSearchingUntilFirstHit(user, ldapConnection, userBaseSettings);
        }

    }

    private static LdapEntry existsSearchingUntilFirstHit(final String user, Connection ldapConnection,
            List<Map.Entry<String, Settings>> userBaseSettings) throws Exception {
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
                log.debug("Results for LDAP search for {} in base {} is {}", user, entry.getKey(), result);
            }

            if (result != null && result.size() >= 1) {
                return result.get(0);
            }
        }

        return null;
    }

    private static LdapEntry existsSearchingAllBases(final String user, Connection ldapConnection,
            List<Map.Entry<String, Settings>> userBaseSettings) throws Exception {
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
                log.debug("Results for LDAP search for " + user + " in base " + entry.getKey() + ":\n" + result);
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
