/*
 *   Copyright OpenSearch Contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

package org.opensearch.security.auth;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.privileges.RoleMapper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

/**
 * This is used to inject opendistro-roles into the request when there is no user involved, like periodic plugin
 * background jobs. The roles injection is done using thread-context at transport layer only. You can't inject
 * roles using REST api. Using this we can enforce fine-grained-access-control for the transport layer calls plugins make.
 *
 * Format for the injected string: user_name|role_1,role_2
 * User name is ignored. And roles are opendistro-roles.
 */
final public class RolesInjector {
    private final Logger log = LogManager.getLogger(RolesInjector.class);
    private final AuditLog auditLog;

    public RolesInjector(AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    public Set<String> injectUserAndRoles(final ThreadPool threadPool) {
        final String injectedUserAndRoles = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES);
        if (injectedUserAndRoles == null) {
            return null;
        }
        log.debug("Injected roles: {}", injectedUserAndRoles);

        String[] strs = injectedUserAndRoles.split("\\|");
        if (strs.length == 0) {
            log.error(
                "Roles injected string malformed, could not extract parts. User string was '{}.'" + " Roles injection failed.",
                injectedUserAndRoles
            );
            return null;
        }

        if (StringUtils.isEmpty(StringUtils.trim(strs[0]))) {
            log.error("Username must be provided, injected string was '{}.' Roles injection failed.", injectedUserAndRoles);
            return null;
        }

        if (strs.length < 2 || StringUtils.isEmpty(StringUtils.trim(strs[0]))) {
            log.error("Roles must be provided, injected string was '{}.' Roles injection failed.", injectedUserAndRoles);
            return null;
        }
        Set<String> roles = ImmutableSet.copyOf(strs[1].split(","));

        Map<String, String> customAttributes = threadPool.getThreadContext()
            .getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_CUSTOM_ATTRIBUTES);

        User user = new User(strs[0]).withSecurityRoles(roles).withAttributes(customAttributes);

        addUser(user, threadPool);
        return roles;
    }

    private void addUser(final User user, final ThreadPool threadPool) {
        final ThreadContext ctx = threadPool.getThreadContext();

        if (ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER) == null) {
            ctx.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        }
        if (ctx.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER) == null) {
            ctx.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, new UserSubjectImpl(threadPool, user));
        }
    }

    /**
     * For users injected by this class, no role mapping shall be performed. This RoleMapper checks whether there
     * is an injected user (by header) and skips default role mapping (realized by the delegate) if so.
     */
    public static class InjectedRoleMapper implements RoleMapper {

        private final ThreadContext threadContext;
        private final RoleMapper defaultRoleMapper;

        public InjectedRoleMapper(RoleMapper defaultRoleMapper, ThreadContext threadContext) {
            this.threadContext = threadContext;
            this.defaultRoleMapper = defaultRoleMapper;
        }

        @Override
        public ImmutableSet<String> map(User user, TransportAddress caller) {
            ImmutableSet<String> mappedRoles;

            if (threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES) != null) {
                // Just return the security roles, like they were initialized in the injectUserAndRoles() method above
                mappedRoles = user.getSecurityRoles();
            } else {
                // No injected user => use default role mapping
                mappedRoles = defaultRoleMapper.map(user, caller);
            }

            String injectedRolesValidationString = threadContext.getTransient(
                ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION
            );
            if (injectedRolesValidationString != null) {
                // Moved from
                // https://github.com/opensearch-project/security/blob/d29095f26dba1a26308c69b608dc926bd40c0f52/src/main/java/org/opensearch/security/privileges/PrivilegesEvaluator.java#L406
                // See also https://github.com/opensearch-project/security/pull/1367
                HashSet<String> injectedRolesValidationSet = new HashSet<>(Arrays.asList(injectedRolesValidationString.split(",")));
                if (!mappedRoles.containsAll(injectedRolesValidationSet)) {
                    throw new OpenSearchSecurityException(
                        String.format("No mapping for %s on roles %s", user, injectedRolesValidationSet),
                        RestStatus.FORBIDDEN
                    );
                }
                mappedRoles = ImmutableSet.copyOf(injectedRolesValidationSet);
            }

            return mappedRoles;
        }
    }
}
