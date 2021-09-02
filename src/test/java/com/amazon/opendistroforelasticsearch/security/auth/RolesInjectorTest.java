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
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportRequest;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static com.amazon.opendistroforelasticsearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES;
import static org.junit.Assert.assertEquals;


public class RolesInjectorTest {

    private TransportRequest transportRequest;
    private Task task;
    private AuditLog auditLog;

    @Before
    public void setup() {
        transportRequest = mock(TransportRequest.class);
        task = mock(Task.class);
        auditLog = mock(AuditLog.class);
    }

    @Test
    public void testNotInjected() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        RolesInjector rolesInjector = new RolesInjector(auditLog);
        Set<String> roles = rolesInjector.injectUserAndRoles(transportRequest, "action0", task, threadContext);
        assertEquals(null, roles);
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals(null, user);
    }

    @Test
    public void testInjected() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(OPENDISTRO_SECURITY_INJECTED_ROLES, "user1|role_1,role_2");

        RolesInjector rolesInjector = new RolesInjector(auditLog);
        Set<String> roles = rolesInjector.injectUserAndRoles(transportRequest, "action0", task, threadContext);

        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertEquals("user1", user.getName());
        assertEquals(0, user.getRoles().size());
        assertEquals(2, roles.size());
        assertEquals(true, roles.contains("role_1"));
        assertEquals(true, roles.contains("role_2"));
    }

    @Test
    public void testCorruptedInjection() {
        List<String> corruptedStrs = Arrays.asList(
                "invalid",
                "role_1,role_2",
                " | ",
                "  ",
                "|"
        );

        corruptedStrs.forEach(name -> {
            ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
            threadContext.putTransient(OPENDISTRO_SECURITY_INJECTED_ROLES, name);

            RolesInjector rolesInjector = new RolesInjector(auditLog);
            Set<String> roles = rolesInjector.injectUserAndRoles(transportRequest, "action0", task, threadContext);

            assertEquals(null, roles);
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            assertEquals(null, user);
        });
    }
}
