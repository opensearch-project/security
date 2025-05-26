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

package org.opensearch.security.auth.ldap.backend;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.ImpersonationBackend;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap.util.LdapHelper;
import org.opensearch.security.auth.ldap.util.Utils;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchScope;

import static org.opensearch.security.setting.DeprecatedSettings.checkForDeprecatedSetting;

public class LDAPAuthenticationBackend implements AuthenticationBackend, ImpersonationBackend {

    static final int ZERO_PLACEHOLDER = 0;
    static final String DEFAULT_USERBASE = "";
    static final String DEFAULT_USERSEARCH_PATTERN = "(sAMAccountName={0})";

    protected static final Logger log = LogManager.getLogger(LDAPAuthenticationBackend.class);

    private final Settings settings;
    private final Path configPath;
    private final List<Map.Entry<String, Settings>> userBaseSettings;
    private final int customAttrMaxValueLen;
    private final WildcardMatcher allowlistedCustomLdapAttrMatcher;

    private final String[] returnAttributes;
    private final boolean shouldFollowReferrals;

    public LDAPAuthenticationBackend(final Settings settings, final Path configPath) {
        this.settings = settings;
        this.configPath = configPath;
        this.userBaseSettings = getUserBaseSettings(settings);
        this.returnAttributes = settings.getAsList(ConfigConstants.LDAP_RETURN_ATTRIBUTES, Arrays.asList(ReturnAttributes.ALL.value()))
            .toArray(new String[0]);
        this.shouldFollowReferrals = settings.getAsBoolean(ConfigConstants.FOLLOW_REFERRALS, ConfigConstants.FOLLOW_REFERRALS_DEFAULT);

        customAttrMaxValueLen = settings.getAsInt(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 36);
        checkForDeprecatedSetting(settings, ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST, ConfigConstants.LDAP_CUSTOM_ATTR_ALLOWLIST);
        final List<String> customAttrAllowList = settings.getAsList(
            ConfigConstants.LDAP_CUSTOM_ATTR_ALLOWLIST,
            settings.getAsList(ConfigConstants.LDAP_CUSTOM_ATTR_WHITELIST, Collections.singletonList("*"))
        );
        allowlistedCustomLdapAttrMatcher = WildcardMatcher.from(customAttrAllowList);
    }

    @Override
    public User authenticate(AuthenticationContext context) throws OpenSearchSecurityException {

        Connection ldapConnection = null;
        final String user = context.getCredentials().getUsername();
        byte[] password = context.getCredentials().getPassword();

        try {
            LdapEntry entry;
            String dn;
            ConnectionConfig connectionConfig;

            try {
                ldapConnection = LDAPAuthorizationBackend.getConnection(settings, configPath);

                entry = exists(user, ldapConnection, settings, userBaseSettings, this.returnAttributes, this.shouldFollowReferrals);

                // fake a user that no exists
                // makes guessing if a user exists or not harder when looking on the
                // authentication delay time
                if (entry == null && settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)) {
                    String fakeLognDn = settings.get(
                        ConfigConstants.LDAP_FAKE_LOGIN_DN,
                        "CN=faketomakebindfail,DC=" + UUID.randomUUID().toString()
                    );
                    entry = new LdapEntry(fakeLognDn);
                    password = settings.get(ConfigConstants.LDAP_FAKE_LOGIN_PASSWORD, "fakeLoginPwd123").getBytes(StandardCharsets.UTF_8);
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

            // Make LdapEntry available to authz backends by adding it to the AuthencationContext
            context.addContextData(LdapEntry.class, entry);

            // by default all ldap attributes which are not binary and with a max value
            // length of 36 are included in the user object
            // if the allowlist contains at least one value then all attributes will be
            // additional check if allowlisted (allowlist can contain wildcard and regex)
            ImmutableMap<String, String> userAttributes = extractLdapAttributes(
                user,
                entry,
                customAttrMaxValueLen,
                allowlistedCustomLdapAttrMatcher
            );
            return new User(username, ImmutableSet.of(), ImmutableSet.of(), null, userAttributes, false);
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
    public Optional<User> impersonate(User user) {
        Connection ldapConnection = null;
        String userName = user.getName();

        try {
            ldapConnection = LDAPAuthorizationBackend.getConnection(settings, configPath);
            LdapEntry userEntry = exists(
                userName,
                ldapConnection,
                settings,
                userBaseSettings,
                this.returnAttributes,
                this.shouldFollowReferrals
            );

            if (userEntry != null) {
                return Optional.of(
                    user.withAttributes(extractLdapAttributes(userName, userEntry, customAttrMaxValueLen, allowlistedCustomLdapAttrMatcher))
                );
            } else {
                return Optional.empty();
            }
        } catch (final Exception e) {
            log.warn("User {} does not exist due to exception", userName, e);
            return Optional.empty();
        } finally {
            Utils.unbindAndCloseSilently(ldapConnection);
        }
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

    static LdapEntry exists(
        final String user,
        Connection ldapConnection,
        Settings settings,
        List<Map.Entry<String, Settings>> userBaseSettings,
        String[] returnAttributes,
        final boolean shouldFollowReferrals
    ) throws Exception {
        if (settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)
            || settings.getAsBoolean(ConfigConstants.LDAP_SEARCH_ALL_BASES, false)
            || settings.hasValue(ConfigConstants.LDAP_AUTHC_USERBASE)) {
            return existsSearchingAllBases(user, ldapConnection, userBaseSettings, returnAttributes, shouldFollowReferrals);
        } else {
            return existsSearchingUntilFirstHit(user, ldapConnection, userBaseSettings, returnAttributes, shouldFollowReferrals);
        }

    }

    private static LdapEntry existsSearchingUntilFirstHit(
        final String user,
        Connection ldapConnection,
        List<Map.Entry<String, Settings>> userBaseSettings,
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
                log.debug("Results for LDAP search for {} in base {} is {}", user, entry.getKey(), result);
            }

            if (result != null && result.size() >= 1) {
                return result.get(0);
            }
        }

        return null;
    }

    private static LdapEntry existsSearchingAllBases(
        final String user,
        Connection ldapConnection,
        List<Map.Entry<String, Settings>> userBaseSettings,
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

    /**
     * Support functionality to extract user attributes from an LdapEntry object.
     * <p>
     * This functionality makes sure that:
     * <ul>
     *     <li>The attributes ldap.original.username and ldap.dn are initialized</li>
     *     <li>Only attributes of a specified max length are considered (in order to limit the size of the user object)</li>
     *     <li>That only allowlisted attributes are added</li>
     * </ul>
     * Originally located in the LdapUser class: https://github.com/nibix/security/blob/5bc2523535228cca9353054970bd8ac040b79023/src/main/java/com/amazon/dlic/auth/ldap/LdapUser.java#L84
     */
    public static ImmutableMap<String, String> extractLdapAttributes(
        String originalUsername,
        LdapEntry userEntry,
        int customAttrMaxValueLen,
        WildcardMatcher allowlistedCustomLdapAttrMatcher
    ) {
        ImmutableMap.Builder<String, String> attributes = ImmutableMap.builder();
        attributes.put("ldap.original.username", originalUsername);
        attributes.put("ldap.dn", userEntry.getDn());

        if (customAttrMaxValueLen > 0) {
            for (LdapAttribute attr : userEntry.getAttributes()) {
                if (attr != null && !attr.isBinary() && !attr.getName().toLowerCase().contains("password")) {
                    final String val = Utils.getSingleStringValue(attr);
                    // only consider attributes which are not binary and where its value is not
                    // longer than customAttrMaxValueLen characters
                    if (val != null && !val.isEmpty() && val.length() <= customAttrMaxValueLen) {
                        if (allowlistedCustomLdapAttrMatcher.test(attr.getName())) {
                            attributes.put("attr.ldap." + attr.getName(), val);
                        }
                    }
                }
            }
        }
        return attributes.build();
    }
}
