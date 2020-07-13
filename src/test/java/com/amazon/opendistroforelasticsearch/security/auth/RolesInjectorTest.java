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

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.auditlog.NullAuditLog;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import static com.amazon.opendistroforelasticsearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES;
import static com.amazon.opendistroforelasticsearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_ENABLED;
import static org.junit.Assert.assertEquals;
import org.junit.Test;


public class RolesInjectorTest {

    @Test
    public void testDisabled() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        Settings settings = Settings.EMPTY;
        RolesInjector rolesInjector = new RolesInjector(settings, threadContext);

        assertEquals(false, rolesInjector.isRoleInjected());
        assertEquals(null, rolesInjector.getUser());
        assertEquals(null, rolesInjector.getInjectedRoles());
    }

    @Test
    public void testEnabledAndInjected() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(OPENDISTRO_SECURITY_INJECTED_ROLES, "user1|role_1,role_2");
        Settings settings = Settings.builder().put(OPENDISTRO_SECURITY_INJECTED_ROLES_ENABLED,"true").build();
        AuditLog auditLog = new NullAuditLog();

        RolesInjector rolesInjector = new RolesInjector(settings, threadContext);
        assertEquals(true, rolesInjector.isRoleInjected());
        assertEquals("user1", rolesInjector.getUser().getName());
        assertEquals(0, rolesInjector.getUser().getRoles().size());
        assertEquals(2, rolesInjector.getInjectedRoles().size());
        assertEquals(true, rolesInjector.getInjectedRoles().contains("role_1"));
        assertEquals(true, rolesInjector.getInjectedRoles().contains("role_2"));
    }
}
