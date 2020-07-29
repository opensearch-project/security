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
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashSet;
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

    public RolesInjector() {
        //empty
    }

    public Set<String> injectUserAndRoles(final ThreadContext ctx) {

        if(log.isDebugEnabled()){
            log.debug("Injected role str: "+ ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES));
        }
        String injectedStr = ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES);
        if (Strings.isNullOrEmpty(injectedStr)) {
            return null;
        }
        User user = parseUser(injectedStr);
        Set<String> roles = parseRoles(injectedStr);
        if(user != null && roles != null) {
            addRemoteAddr(ctx);
            addUser(user, ctx);
        }
        return roles;
    }

    private void addRemoteAddr(final ThreadContext threadContext) {
        if(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS) != null)
            return;

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS,
                new TransportAddress(InetAddress.getLoopbackAddress(), 9300));
    }

    private void addUser(final User user, final ThreadContext threadContext) {
        if(threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER) != null)
            return;

        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
    }

    /*
     * Input string format: user|role_1,role2
     */
    private User parseUser(final String injectedStr) {
        String[] strs = injectedStr.split("\\|");
        if (strs.length == 0) {
            log.error("Roles injected string malformed, could not extract parts. User string was '{}.'" +
                    " Roles injection failed.", injectedStr);
            return null;
        }
        if (Strings.isNullOrEmpty(strs[0].trim())) {
            log.error("Username must not be null, injected string was '{}.' Roles injection failed.", injectedStr);
            return null;
        }
        return new User(strs[0]);
    }

    /*
     * Input string format: user|role_1,role2
     */
    private Set<String> parseRoles(final String injectedStr) {
        String[] strs = injectedStr.split("\\|");
        if (strs.length == 1) {
            log.error("Roles injected string malformed, could not extract parts. User string was '{}.'" +
                    " Roles injection failed.", injectedStr);
            return null;
        }
        if (Strings.isNullOrEmpty(strs[1].trim())) {
            log.error("Roles must not be null, injected string was '{}.' Roles injection failed.", injectedStr);
            return null;
        }
        return new HashSet<>(Arrays.asList(strs[1].split(",")));
    }
}
