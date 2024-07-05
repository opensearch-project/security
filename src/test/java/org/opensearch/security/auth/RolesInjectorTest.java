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
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES;
import static org.mockito.Mockito.mock;

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
        assertThat(roles, is(nullValue()));
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertThat(user, is(nullValue()));
    }

    @Test
    public void testInjected() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(OPENDISTRO_SECURITY_INJECTED_ROLES, "user1|role_1,role_2");

        RolesInjector rolesInjector = new RolesInjector(auditLog);
        Set<String> roles = rolesInjector.injectUserAndRoles(transportRequest, "action0", task, threadContext);

        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        assertThat(user.getName(), is("user1"));
        assertThat(user.getRoles().size(), is(0));
        assertThat(roles.size(), is(2));
        assertThat(roles.contains("role_1"), is(true));
        assertThat(roles.contains("role_2"), is(true));
    }

    @Test
    public void testCorruptedInjection() {
        List<String> corruptedStrs = Arrays.asList("invalid", "role_1,role_2", " | ", "  ", "|");

        corruptedStrs.forEach(name -> {
            ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
            threadContext.putTransient(OPENDISTRO_SECURITY_INJECTED_ROLES, name);

            RolesInjector rolesInjector = new RolesInjector(auditLog);
            Set<String> roles = rolesInjector.injectUserAndRoles(transportRequest, "action0", task, threadContext);

            assertThat(roles, is(nullValue()));
            User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            assertThat(user, is(nullValue()));
        });
    }
}
