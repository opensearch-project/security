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

package com.amazon.opendistroforelasticsearch.security.auth;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * This is used to inject opendistro-roles into the request when there is no user involved like periodic plugin 
 * background jobs. The roles injection is done using thread-context at transport layer only. You can't inject 
 * roles using REST api. Using this we can enforce fine-grained-access-control for the calls plugins make.
 * 
 * Format for the injected string: user_name|role_1,role_2
 * User name is ignored.
 */

final public class RolesInjector {
    protected final Logger log = LogManager.getLogger(RolesInjector.class);
    private final boolean enabled;
    private User user = null;
    private Set<String> roles = null;
    private final ThreadContext threadContext;

    public RolesInjector(final Settings settings, final ThreadContext ctx) {
        this.threadContext = ctx;
        this.enabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_ENABLED, true);

        parseInjectedStr(ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES));
        if(log.isDebugEnabled()){
            log.debug("Injected role str: "+ ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES));
        }
        addRemoteAddr(threadContext);
    }

    private void addRemoteAddr(ThreadContext threadContext) {
        if(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS) != null)
            return;

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS,
                new TransportAddress(InetAddress.getLoopbackAddress(), 9300));
    }

    /*
     * Input string format: user|role_1,role2
     */
    private void parseInjectedStr(final String injectedStr) {
        if (Strings.isNullOrEmpty(injectedStr))
            return;

        String[] strs = injectedStr.split("\\|");
        if (strs.length == 0) {
            log.error("Roles injected string malformed, could not extract parts. User string was '{}.'" +
                    " Roles injection failed.", injectedStr);
            return;
        }
        if (Strings.isNullOrEmpty(strs[0])) {
            log.error("Username must not be null, injected string was '{}.' Roles injection failed.", injectedStr);
            return;
        }
        this.user = new User(strs[0]);
        this.roles = new HashSet<>();
        if (Strings.isNullOrEmpty(strs[1])) {
            log.error("Roles must not be null, injected string was '{}.' Roles injection failed.", injectedStr);
            return;
        }
        roles.addAll(Arrays.asList(strs[1].split(",")));
    }

    public boolean isRoleInjected() {
        return enabled && (user != null) && (roles.size() > 0);
    }

    public final Set<String> getInjectedRoles() {
        return roles;
    }

    public final User getUser() {
        return user;
    }
}
