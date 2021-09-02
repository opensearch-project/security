/*
 *   Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import com.google.common.collect.ImmutableSet;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportRequest;

import java.util.Set;

/**
 * This is used to inject opendistro-roles into the request when there is no user involved, like periodic plugin
 * background jobs. The roles injection is done using thread-context at transport layer only. You can't inject
 * roles using REST api. Using this we can enforce fine-grained-access-control for the transport layer calls plugins make.
 *
 * Format for the injected string: user_name|role_1,role_2
 * User name is ignored. And roles are opendistro-roles.
 */
final public class RolesInjector {
    protected final Logger log = LogManager.getLogger(RolesInjector.class);
    private final AuditLog auditLog;

    public RolesInjector(AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    public Set<String> injectUserAndRoles(TransportRequest transportRequest, String action, Task task, final ThreadContext ctx) {
        final String injectedUserAndRoles = ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES);
        if (injectedUserAndRoles == null) {
            return null;
        }
        log.debug("Injected roles: {}", injectedUserAndRoles);

        String[] strs = injectedUserAndRoles.split("\\|");
        if (strs.length == 0) {
            log.error("Roles injected string malformed, could not extract parts. User string was '{}.'" +
                    " Roles injection failed.", injectedUserAndRoles);
            return null;
        }

        if (StringUtils.isEmpty(StringUtils.trim(strs[0]))) {
            log.error("Username must be provided, injected string was '{}.' Roles injection failed.", injectedUserAndRoles);
            return null;
        }
        User user = new User(strs[0]);

        if (strs.length < 2 || StringUtils.isEmpty(StringUtils.trim(strs[0]))) {
            log.error("Roles must be provided, injected string was '{}.' Roles injection failed.", injectedUserAndRoles);
            return null;
        }
        Set<String> roles = ImmutableSet.copyOf(strs[1].split(","));

        if(user != null && roles != null) {
            addUser(user, transportRequest, action, task, ctx);
        }
        return roles;
    }

    private void addUser(final User user, final TransportRequest transportRequest,
                         final String action, final Task task, final ThreadContext threadContext) {
        if(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER) != null)
            return;

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        auditLog.logSucceededLogin(user.getName(), false, null, transportRequest, action, task);
    }
}
