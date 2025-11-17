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
package org.opensearch.security.user;

import java.util.HashMap;
import java.util.StringJoiner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.TenantPrivileges;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.SecuritySettings;

import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT;
import static org.opensearch.security.support.ConfigConstants.USER_ATTRIBUTE_SERIALIZATION_ENABLED;
import static org.opensearch.security.support.ConfigConstants.USER_ATTRIBUTE_SERIALIZATION_ENABLED_DEFAULT;
import static org.opensearch.security.support.SecurityUtils.escapePipe;

/**
 * Functionality to add parseable information about the current user to the thread context. Usually called
 * in the SecurityFilter.
 * <p>
 * Moved from https://github.com/opensearch-project/security/blob/d29095f26dba1a26308c69b608dc926bd40c0f52/src/main/java/org/opensearch/security/privileges/PrivilegesEvaluator.java#L293
 */
public class ThreadContextUserInfo {
    protected static final Logger log = LogManager.getLogger(ThreadContextUserInfo.class);

    private static final String READ_ACCESS = "READ";
    private static final String WRITE_ACCESS = "WRITE";
    private static final String NO_ACCESS = "NONE";
    private static final String GLOBAL_TENANT = "global_tenant";

    private volatile boolean userAttributeSerializationEnabled;
    private final ThreadContext threadContext;
    private final PrivilegesConfiguration privilegesConfiguration;

    public ThreadContextUserInfo(
        ThreadContext threadContext,
        PrivilegesConfiguration privilegesConfiguration,
        ClusterSettings clusterSettings,
        Settings settings
    ) {
        this.threadContext = threadContext;
        this.userAttributeSerializationEnabled = settings.getAsBoolean(
            USER_ATTRIBUTE_SERIALIZATION_ENABLED,
            USER_ATTRIBUTE_SERIALIZATION_ENABLED_DEFAULT
        );
        this.privilegesConfiguration = privilegesConfiguration;
        clusterSettings.addSettingsUpdateConsumer(
            SecuritySettings.USER_ATTRIBUTE_SERIALIZATION_ENABLED_SETTING,
            newIsUserAttributeSerializationEnabled -> {
                userAttributeSerializationEnabled = newIsUserAttributeSerializationEnabled;
            }
        );
    }

    public void setUserInfoInThreadContext(PrivilegesEvaluationContext context) {
        if (threadContext.getTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT) == null) {
            StringJoiner joiner = new StringJoiner("|");
            // Escape any pipe characters in the values before joining
            joiner.add(escapePipe(context.getUser().getName()));
            joiner.add(escapePipe(String.join(",", context.getUser().getRoles())));
            joiner.add(escapePipe(String.join(",", context.getMappedRoles())));

            String requestedTenant = context.getUser().getRequestedTenant();
            joiner.add(requestedTenant);

            String tenantAccessToCheck = getTenancyAccess(context);
            joiner.add(tenantAccessToCheck);
            log.debug("userInfo: {}", joiner);

            if (userAttributeSerializationEnabled) {
                joiner.add(Base64Helper.serializeObject(new HashMap<>(context.getUser().getCustomAttributesMap())));
            }

            threadContext.putTransient(OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT, joiner.toString());
        }
    }

    private String getTenancyAccess(PrivilegesEvaluationContext context) {
        String requestedTenant = context.getUser().getRequestedTenant();
        TenantPrivileges tenantPrivileges = privilegesConfiguration.tenantPrivileges();
        final String tenant = Strings.isNullOrEmpty(requestedTenant) ? GLOBAL_TENANT : requestedTenant;
        if (tenantPrivileges.hasTenantPrivilege(context, tenant, TenantPrivileges.ActionType.WRITE)) {
            return WRITE_ACCESS;
        } else if (tenantPrivileges.hasTenantPrivilege(context, tenant, TenantPrivileges.ActionType.READ)) {
            return READ_ACCESS;
        } else {
            return NO_ACCESS;
        }
    }
}
