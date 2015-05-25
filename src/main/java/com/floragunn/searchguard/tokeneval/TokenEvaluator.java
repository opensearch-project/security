/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.tokeneval;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;

import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.util.SecurityUtil;
import com.google.common.collect.Lists;

public class TokenEvaluator {

    private final static ObjectMapper mapper = new ObjectMapper();
    protected static final ESLogger log = Loggers.getLogger(TokenEvaluator.class);
    protected final BytesReference xSecurityConfiguration;

    static {
        mapper.configure(DeserializationConfig.Feature.READ_ENUMS_USING_TO_STRING, true);
        mapper.configure(DeserializationConfig.Feature.FAIL_ON_NULL_FOR_PRIMITIVES, true);
        mapper.configure(DeserializationConfig.Feature.FAIL_ON_NUMBERS_FOR_ENUMS, true);
        mapper.configure(DeserializationConfig.Feature.FAIL_ON_UNKNOWN_PROPERTIES, true);
    }

    public enum FilterAction {

        EXECUTE, BYPASS

    }

    public TokenEvaluator(final BytesReference xSecurityConfiguration) {
        super();

        if (xSecurityConfiguration == null || xSecurityConfiguration.length() == 0) {
            throw new IllegalArgumentException("securityconfiguration must not be null or empty");
        }

        this.xSecurityConfiguration = xSecurityConfiguration;
        log.trace("Configuration: " + xSecurityConfiguration.toUtf8());
    }

    public Evaluator getEvaluator(List<String> requestedIndices, List<String> requestedAliases, List<String> requestedTypes,
            final InetAddress requestedHostAddress, final User user) throws MalformedConfigurationException {

        if (requestedIndices == null || requestedIndices.isEmpty()) {
            requestedIndices = Lists.newArrayList("*");
        }

        if (requestedAliases == null || requestedAliases.isEmpty()) {
            requestedAliases = Lists.newArrayList("*");
        }

        if (requestedTypes == null || requestedTypes.isEmpty()) {
            requestedTypes = Lists.newArrayList("*");
        }

        final String requestedClientHostName = requestedHostAddress == null ? null : requestedHostAddress.getHostName();
        final String requestedClientHostIp = requestedHostAddress == null ? null : requestedHostAddress.getHostAddress();

        log.debug("user {}", user);
        log.debug("requestedHostAddress: {} OR {}", requestedClientHostIp, requestedClientHostName);
        log.debug("requestedAliases: {}", requestedAliases);
        log.debug("requestedIndices: {}", requestedIndices);
        log.debug("requestedTypes: {}", requestedTypes);

        final Set<String> filtersExecute = new HashSet<String>();
        final Set<String> filterBypass = new HashSet<String>();
        ACRules acRules = null;

        try {
            acRules = mapper.readValue(xSecurityConfiguration.toBytes(), ACRules.class);
        } catch (final Exception e) {
            throw new MalformedConfigurationException(e);
        }

        log.debug("Checking " + (acRules.getAcl().size() - 1) + " rules");
        boolean foundDefault = false;

        for (final ACRule p : acRules.acl) {

            if (p.isDefault()) {

                filtersExecute.addAll(p.getFilters_execute());
                filterBypass.addAll(p.getFilters_bypass());

                if (log.isDebugEnabled()) {
                    log.debug("Default set to filtersExecute " + filtersExecute);
                    log.debug("Default set to filterBypass " + filterBypass);
                }

                if (foundDefault) {
                    throw new MalformedConfigurationException("More than one default configuration found");
                }

                foundDefault = true;

            }
        }

        if (!foundDefault) {
            throw new MalformedConfigurationException("No default configuration found");
        }

        int rulenum = 1;
        ruleloop: for (final ACRule p : acRules.acl) {

            if (p.isDefault()) {
                continue;
            }

            if (p.getFilters_bypass() == null) {
                throw new MalformedConfigurationException("bypass filters missing");
            }

            if (p.getFilters_execute() == null) {
                throw new MalformedConfigurationException("execute filters missing");
            }

            String _role = null;
            String _host = null;

            log.debug("Check rule {}.: {}", rulenum, p);
            rulenum++;

            boolean userMatch = false;
            boolean roleMatch = false;
            boolean hostMatch = false;

            //-- Users -------------------------------------------

            // //[] == ["...","*","..."] == missing/not-here (because empty)
            if (!isNullEmtyStar(p.users)) {
                if (containsWildcardPattern(p.users, user.getName())) {
                    log.debug("    --> User " + user.getName() + " match");
                    userMatch = true;
                } else {
                    log.debug("    User " + user.getName() + " does not match");
                }

            } else {
                userMatch = true;
                log.debug("    --> User wildcard match");
            }

            //-- Roles -------------------------------------------

            if (!isNullEmtyStar(p.roles)) {
                for (final String role : p.roles) {
                    if (containsWildcardPattern(user.getRoles(), role)) {
                        log.debug("    --> User has role " + role + ", so we have a match");
                        _role = role;
                        roleMatch = true;
                        break;
                    } else {
                        log.debug("    User does not have role " + role);
                    }
                }

                if (_role == null) {
                    log.debug("    No role does not match");
                }
            } else {
                roleMatch = true;
                log.debug("    --> Role wildcard match");
            }

            //-- Hosts -------------------------------------------

            if (requestedClientHostIp != null && requestedClientHostName != null && !isNullEmtyStar(p.hosts)) {
                for (final String pinetAddress : p.hosts) {
                    if (SecurityUtil.isWildcardMatch(requestedClientHostName, pinetAddress, false)
                            || SecurityUtil.isWildcardMatch(requestedClientHostIp, pinetAddress, false)) {

                        log.debug("    --> Host address " + pinetAddress + " match");
                        _host = pinetAddress;
                        hostMatch = true;
                        break;

                    }

                }

                if (_host == null) {

                    log.debug("    Host address " + requestedClientHostIp + " (ip) and " + requestedClientHostName
                            + " (hostname) does not match");
                }

            } else {
                hostMatch = true;
                log.debug("    --> Host wildcard match");
            }

            if (!hostMatch || !roleMatch || !userMatch) {
                log.debug("    --> Users or roles or hosts does not match, so we skip this rule");
                continue ruleloop;
            } else {
                log.debug("    Identity would match, see if aliases and indices are also ok?");
            }

            //-- Aliases -------------------------------------------

            //[] == ["...","*","..."] == missing (because empty)
            if (!isNullEmtyStar(p.aliases)) {

                aliasloop: for (final String requestedAlias : requestedAliases) {

                    boolean aliasok = false;

                    for (final String pAlias : p.aliases) {

                        if (typeAndMatch(requestedAlias, pAlias, requestedTypes)) {
                            log.debug("    --> Alias " + requestedAlias + " match " + pAlias + "");
                            aliasok = true;
                            break;

                        } else {
                            log.debug("    Alias " + requestedAlias + " not match " + pAlias + "");

                        }

                    }

                    if (aliasok) {
                        log.debug("    Alias " + requestedAlias + " has a matching pattern");
                        continue aliasloop;
                    } else {
                        log.debug("    --> Alias " + requestedAlias + " does not have a matching pattern, skip this rule");
                        //allAliasesMatch = false;
                        continue ruleloop;
                    }

                }

            } else {
                log.debug("    --> Alias wildcard match");
            }

            //-- Indices -------------------------------------------

            if (!isNullEmtyStar(p.indices)) {

                indexloop: for (final String requestedIndex : requestedIndices) {

                    boolean indexok = false;

                    for (final String pIndex : p.indices) {

                        if (typeAndMatch(requestedIndex, pIndex, requestedTypes)) {
                            log.debug("    -->Index " + requestedIndex + " match " + pIndex + "");
                            indexok = true;
                            break;

                        } else {
                            log.debug("    Index " + requestedIndex + " not match " + pIndex + "");

                        }

                    }

                    if (indexok) {
                        log.debug("    Index " + requestedIndex + " has a matching pattern");
                        continue indexloop;
                    } else {
                        log.debug("    --> Index " + requestedIndex + " does not have a matching pattern, skip this rule");
                        continue ruleloop;
                    }

                }

            } else {
                log.debug("    --> Index wildcard match");
            }

            log.debug("    ----> APPLY RULE <---- which means the following executeFilters: {}/bypassFilters: {}", p.getFilters_execute(),
                    p.getFilters_bypass());
            filtersExecute.addAll(p.getFilters_execute());
            filterBypass.addAll(p.getFilters_bypass());

        }// end ruleloop

        log.debug("Final executeFilters: {}/bypassFilters: {}", filtersExecute, filterBypass);

        return new Evaluator(filterBypass, filtersExecute);

    }

    private static boolean typeAndMatch(final String requested, final String granted, final List<String> requestedTypes) {

        log.debug("typeAndMatch(): request {}, granted {}, requestedTypes {}", requested, granted, requestedTypes);

        final String[] grantedA = granted.split(":");

        if (grantedA.length > 1 && (requestedTypes == null || requestedTypes.size() == 0 || requestedTypes.contains("*"))) {
            return false;
        }

        if (SecurityUtil.isWildcardMatch(requested, grantedA[0], false)) {

            log.debug("Wildcard indices/aliases: {} -> {}", requested, grantedA[0]);
            if (grantedA.length > 1) {
                for (final Iterator iterator = requestedTypes.iterator(); iterator.hasNext();) {
                    final String requestedType = (String) iterator.next();
                    if (!SecurityUtil.isWildcardMatch(requestedType, grantedA[1], false)) {
                        log.debug("Wildcard types: {} -> {}", requestedType, grantedA[1]);
                        return false;
                    }
                }

                return true;

            } else {
                //grantedA.length is 1
                log.debug("Wildcard without types: {} -> {}", requested, grantedA[0]);
                return true;
            }

        }

        return false;
    }

    public static class Evaluator implements Serializable {

        /**
         * 
         */
        private static final long serialVersionUID = 1L;
        private final Set<String> bypassFilters;
        private final Set<String> executeFilters;

        public Evaluator(final Set<String> bypassFlters, final Set<String> executeFilters) throws MalformedConfigurationException {
            super();
            this.bypassFilters = bypassFlters;
            this.executeFilters = executeFilters;
            validateAndMerge();
        }

        private void validateAndMerge() throws MalformedConfigurationException {

            if (!Collections.disjoint(bypassFilters, executeFilters)) {
                log.warn("Identical execute and bypass filters");
                log.warn("    bypassFilters: {}", bypassFilters);
                log.warn("    executeFilters: {}", executeFilters);
            }

            if (bypassFilters.isEmpty() && executeFilters.isEmpty()) {
                throw new MalformedConfigurationException("no bypass or execute filters at all");
            }
        }

        public boolean getBypassAll() {
            return bypassFilters.contains("*");
        }

        public boolean getExecuteAll() {
            return executeFilters.contains("*") && bypassFilters.isEmpty();
        }

        public FilterAction evaluateFilter(final String ft, final String fn) {

            final String filter = ft + "." + fn;

            if (getExecuteAll()) {
                return FilterAction.EXECUTE;
            }

            if (getBypassAll()) {
                return FilterAction.BYPASS;
            }

            if (containsWildcardPattern(bypassFilters, filter)) {
                return FilterAction.BYPASS;
            }

            if (containsWildcardPattern(executeFilters, filter) || executeFilters.contains("*")) {
                return FilterAction.EXECUTE;
            }

            return FilterAction.BYPASS;
        }

    }

    @SuppressWarnings(value = { "unused" })
    private static class ACRules {

        private List<ACRule> acl;

        public final List<ACRule> getAcl() {
            return acl;
        }

        public final void setAcl(final List<ACRule> acl) {
            this.acl = acl;
        }
    }

    @SuppressWarnings(value = { "unused" })
    private static class ACRule {

        private String __Comment__;
        private Set<String> hosts;
        private Set<String> users;
        private Set<String> roles;
        private Set<String> indices;
        private Set<String> aliases;
        private Set<String> filters_execute;
        private Set<String> filters_bypass;

        public boolean isDefault() {

            if (isNullEmtyStar(hosts) && isNullEmtyStar(users) && isNullEmtyStar(roles) && isNullEmtyStar(indices)
                    && isNullEmtyStar(aliases)) {
                return true;
            }

            return false;
        }

        public final String get__Comment__() {
            return __Comment__;
        }

        public final void set__Comment__(final String __Comment__) {
            this.__Comment__ = __Comment__;
        }

        public final Set<String> getHosts() {
            return hosts;
        }

        public final void setHosts(final Set<String> hosts) {
            this.hosts = hosts;
        }

        public final Set<String> getUsers() {
            return users;
        }

        public final void setUsers(final Set<String> users) {
            this.users = users;
        }

        public final Set<String> getRoles() {
            return roles;
        }

        public final void setRoles(final Set<String> roles) {
            this.roles = roles;
        }

        public final Set<String> getIndices() {
            return indices;
        }

        public final void setIndices(final Set<String> indices) {
            this.indices = indices;
        }

        public final Set<String> getAliases() {
            return aliases;
        }

        public final void setAliases(final Set<String> aliases) {
            this.aliases = aliases;
        }

        public final Set<String> getFilters_execute() {
            return filters_execute;
        }

        public final void setFilters_execute(final Set<String> filters_execute) {
            this.filters_execute = filters_execute;
        }

        public final Set<String> getFilters_bypass() {
            return filters_bypass;
        }

        public final void setFilters_bypass(final Set<String> filters_bypass) {
            this.filters_bypass = filters_bypass;
        }

        @Override
        public String toString() {
            return "ACRule [hosts=" + hosts + ", users=" + users + ", roles=" + roles + ", indices=" + indices + ", aliases=" + aliases
                    + ", filters_execute=" + filters_execute + ", filters_bypass=" + filters_bypass + ", isDefault()=" + isDefault()
                    + ", __Comment__=\"" + __Comment__ + "\"]";
        }
    }

    private static boolean isNullEmtyStar(final Set<String> set) {
        if (set == null || set.isEmpty() || set.contains("*")) {
            return true;
        }

        return false;

    }

    private static boolean containsWildcardPattern(final Set<String> set, final String pattern) {
        for (final Iterator iterator = set.iterator(); iterator.hasNext();) {
            final String string = (String) iterator.next();
            if (SecurityUtil.isWildcardMatch(string, pattern, false)) {
                return true;
            }
        }
        return false;

    }
}
