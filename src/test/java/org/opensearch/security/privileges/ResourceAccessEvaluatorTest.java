/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.util.Collections;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.SubjectBasedActionPrivileges;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ResourceAccessEvaluatorTest {
    @Mock
    private ThreadPool threadPool;

    @Mock
    private ResourceSharingIndexHandler sharingHandler;
    @Mock
    private PrivilegesEvaluationContext context;
    @Mock
    private RoleBasedActionPrivileges roleBasedActionPrivileges;

    private ThreadContext threadContext;
    private ResourceAccessEvaluator evaluator;

    private static final String IDX = "resource-index";

    @Before
    public void setup() {
        threadContext = new ThreadContext(Settings.EMPTY);
        doReturn(threadContext).when(threadPool).getThreadContext();
        evaluator = new ResourceAccessEvaluator(Collections.singleton(IDX), threadPool, sharingHandler);
    }

    private void stubAuthenticatedUser(String username) {
        User user = new User(username);

        UserSubjectImpl subject = mock(UserSubjectImpl.class);
        when(subject.getUser()).thenReturn(user);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
        threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
    }

    @Test
    public void testPublicResource_NotAutomaticallyAllowed() {
        stubAuthenticatedUser("alice");
        var req = new IndexRequest(IDX).id("res1");
        when(context.getActionPrivileges()).thenReturn(roleBasedActionPrivileges);
        doAnswer(inv -> {
            ActionListener<ResourceSharing> listener = inv.getArgument(2);
            var doc = mock(ResourceSharing.class);
            listener.onResponse(doc);
            return null;
        }).when(sharingHandler).fetchSharingInfo(eq(IDX), eq("res1"), any());

        var presponse = new PrivilegesEvaluatorResponse();
        presponse.allowed = false;
        var out = evaluator.evaluate(req, "any:action", context, presponse);

        assertThat(out.allowed, equalTo(false));
        assertThat(out.isComplete(), equalTo(true));
    }

    @Test
    public void testNotSharedDenied() {
        stubAuthenticatedUser("bob");
        var req = new IndexRequest(IDX).id("res2");
        when(context.getActionPrivileges()).thenReturn(roleBasedActionPrivileges);
        doAnswer(inv -> {
            ActionListener<ResourceSharing> listener = inv.getArgument(2);
            var doc = mock(ResourceSharing.class);
            when(doc.isCreatedBy(any())).thenReturn(false);
            when(doc.fetchAccessLevels(any(), any())).thenReturn(Collections.emptySet());
            listener.onResponse(doc);
            return null;
        }).when(sharingHandler).fetchSharingInfo(eq(IDX), eq("res2"), any());

        var presponse = new PrivilegesEvaluatorResponse();
        presponse.allowed = true;
        var out = evaluator.evaluate(req, "read", context, presponse);

        assertThat(out.allowed, equalTo(false));
        assertThat(out.isComplete(), equalTo(true));
    }

    @Test
    public void testOwnerAllowed() {
        stubAuthenticatedUser("ownerUser");
        var req = new IndexRequest(IDX).id("resOwner");
        when(context.getActionPrivileges()).thenReturn(roleBasedActionPrivileges);
        doAnswer(inv -> {
            ActionListener<ResourceSharing> listener = inv.getArgument(2);
            var doc = mock(ResourceSharing.class);
            when(doc.isCreatedBy("ownerUser")).thenReturn(true);
            listener.onResponse(doc);
            return null;
        }).when(sharingHandler).fetchSharingInfo(eq(IDX), eq("resOwner"), any());

        var presponse = new PrivilegesEvaluatorResponse();
        presponse.allowed = false;
        var out = evaluator.evaluate(req, "write", context, presponse);

        assertThat(out.allowed, equalTo(true));
        assertThat(out.isComplete(), equalTo(true));
    }

    @Test
    public void testShareWithAllowed() {
        stubAuthenticatedUser("charlie");
        var req = new IndexRequest(IDX).id("resShared");
        var ag = mock(FlattenedActionGroups.class);
        when(ag.resolve(any())).thenReturn(ImmutableSet.of("read"));
        when(roleBasedActionPrivileges.flattenedActionGroups()).thenReturn(ag);
        when(context.getActionPrivileges()).thenReturn(roleBasedActionPrivileges);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> listener = inv.getArgument(2);
            var doc = mock(ResourceSharing.class);
            when(doc.isCreatedBy(any())).thenReturn(false);
            when(doc.fetchAccessLevels(Recipient.USERS, Set.of("charlie", "*"))).thenReturn(Set.of("read"));
            listener.onResponse(doc);
            return null;
        }).when(sharingHandler).fetchSharingInfo(eq(IDX), eq("resShared"), any());

        var presponse = new PrivilegesEvaluatorResponse();
        presponse.allowed = false;
        var out = evaluator.evaluate(req, "read", context, presponse);

        assertThat(out.allowed, equalTo(true));
        assertThat(out.isComplete(), equalTo(true));
    }

    @Test
    public void testPluginUserNotAllowed() {
        stubAuthenticatedUser("charlie");
        when(context.getActionPrivileges()).thenReturn(mock(SubjectBasedActionPrivileges.class));

        var req = new IndexRequest(IDX).id("resShared");
        var presponse = new PrivilegesEvaluatorResponse();
        presponse.allowed = false;
        var out = evaluator.evaluate(req, "read", context, presponse);

        assertThat(out.allowed, equalTo(false));
        assertThat(out.isComplete(), equalTo(true));
    }

}
