/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.Collections;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.actionlevel.SubjectBasedActionPrivileges;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("unchecked") // action listener mock
public class ResourceAccessHandlerTest {

    @Mock
    private ThreadPool threadPool;
    @Mock
    private ResourceSharingIndexHandler sharingIndexHandler;
    @Mock
    private AdminDNs adminDNs;
    @Mock
    private PrivilegesEvaluator privilegesEvaluator;
    @Mock
    private PrivilegesEvaluationContext context;
    @Mock
    private RoleBasedActionPrivileges roleBasedPrivileges;

    @Mock
    private ResourcePluginInfo resourcePluginInfo;

    private ThreadContext threadContext;
    private ResourceAccessHandler handler;

    private static final String INDEX = "test-index";
    private static final String TYPE = "test";
    private static final String RESOURCE_ID = "res-1";
    private static final String ACTION = "read";

    @Before
    public void setup() {
        threadContext = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        handler = new ResourceAccessHandler(threadPool, sharingIndexHandler, adminDNs, privilegesEvaluator, resourcePluginInfo);

        // For tests that verify permission with action-group
        when(resourcePluginInfo.flattenedForType(any())).thenReturn(mock(FlattenedActionGroups.class));
        when(resourcePluginInfo.indexByType(TYPE)).thenReturn(INDEX);
    }

    private void injectUser(User user) {
        UserSubjectImpl subject = mock(UserSubjectImpl.class);
        when(subject.getUser()).thenReturn(user);
        threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
    }

    @Test
    public void testHasPermission_adminUserAllowed() {
        User user = new User("admin", ImmutableSet.of("admin"), ImmutableSet.of(), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(true);

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, context, listener);

        verify(listener).onResponse(true);
    }

    @Test
    public void testHasPermission_ownerAllowed() {
        User user = new User("alice", ImmutableSet.of("r1"), ImmutableSet.of("b1"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);
        when(privilegesEvaluator.createContext(user, ACTION)).thenReturn(context);
        when(context.getActionPrivileges()).thenReturn(roleBasedPrivileges);

        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.isCreatedBy("alice")).thenReturn(true);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, null, listener);

        verify(listener).onResponse(true);
    }

    @Test
    public void testHasPermission_sharedWithUserAllowed() {
        User user = new User("bob", ImmutableSet.of("role1"), ImmutableSet.of("backend1"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);
        when(privilegesEvaluator.createContext(user, ACTION)).thenReturn(context);
        when(context.getActionPrivileges()).thenReturn(roleBasedPrivileges);

        // Document setup: shared with the user at access-level "read"
        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.isCreatedBy("bob")).thenReturn(false);
        when(doc.fetchAccessLevels(eq(Recipient.USERS), any())).thenReturn(Set.of("read"));
        when(doc.fetchAccessLevels(eq(Recipient.ROLES), any())).thenReturn(Set.of());
        when(doc.fetchAccessLevels(eq(Recipient.BACKEND_ROLES), any())).thenReturn(Set.of());

        FlattenedActionGroups ag = mock(FlattenedActionGroups.class);
        when(resourcePluginInfo.flattenedForType(TYPE)).thenReturn(ag);
        // Resolve the access level "read" to the concrete allowed action "read" (could also be a wildcard)
        when(ag.resolve(any())).thenReturn(ImmutableSet.of("read"));

        // Return the sharing doc from the index handler
        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, null, listener);

        verify(listener).onResponse(true);
    }

    @Test
    public void testHasPermission_noAccessLevelsDenied() {
        User user = new User("charlie", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);
        when(privilegesEvaluator.createContext(user, ACTION)).thenReturn(context);
        when(context.getActionPrivileges()).thenReturn(roleBasedPrivileges);

        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.isCreatedBy("charlie")).thenReturn(false);
        when(doc.fetchAccessLevels(any(), any())).thenReturn(Collections.emptySet());

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, null, listener);

        verify(listener).onResponse(false);
    }

    @Test
    public void testHasPermission_nullDocumentDenied() {
        User user = new User("dave", ImmutableSet.of("x"), ImmutableSet.of("y"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);
        when(privilegesEvaluator.createContext(user, ACTION)).thenReturn(context);
        when(context.getActionPrivileges()).thenReturn(roleBasedPrivileges);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(null);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, null, listener);

        verify(listener).onResponse(false);
    }

    @Test
    public void testHasPermission_pluginUserDenied() {
        User user = new User("plugin_user", ImmutableSet.of(), ImmutableSet.of(), null, ImmutableMap.of(), false);
        injectUser(user);
        PrivilegesEvaluationContext subjectContext = mock(PrivilegesEvaluationContext.class);
        when(subjectContext.getActionPrivileges()).thenReturn(mock(SubjectBasedActionPrivileges.class));
        when(privilegesEvaluator.createContext(user, ACTION)).thenReturn(subjectContext);

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, null, listener);

        verify(listener).onResponse(false);
    }

    @Test
    public void testGetOwnAndSharedResources_asAdmin() {
        User admin = new User("admin", ImmutableSet.of(), ImmutableSet.of(), null, ImmutableMap.of(), false);
        injectUser(admin);
        when(adminDNs.isAdmin(admin)).thenReturn(true);

        ActionListener<Set<String>> listener = mock(ActionListener.class);

        doAnswer(inv -> {
            ActionListener<Set<String>> l = inv.getArgument(1);
            l.onResponse(Set.of("res1", "res2"));
            return null;
        }).when(sharingIndexHandler).fetchAllResourceIds(eq(INDEX), any());

        handler.getOwnAndSharedResourceIdsForCurrentUser(TYPE, listener);
        verify(listener).onResponse(Set.of("res1", "res2"));
    }

    @Test
    public void testGetOwnAndSharedResources_asNormalUser() {
        User user = new User("alice", ImmutableSet.of("r1"), ImmutableSet.of("b1"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        ActionListener<Set<String>> listener = mock(ActionListener.class);

        doAnswer(inv -> {
            ActionListener<Set<String>> l = inv.getArgument(2);
            l.onResponse(Set.of("res1"));
            return null;
        }).when(sharingIndexHandler).fetchAccessibleResourceIds(any(), any(), any());

        handler.getOwnAndSharedResourceIdsForCurrentUser(TYPE, listener);
        verify(listener).onResponse(Set.of("res1"));
    }

    @Test
    public void testShareSuccess() {
        User user = new User("user2", ImmutableSet.of(), ImmutableSet.of(), null, ImmutableMap.of(), false);
        injectUser(user);

        ShareWith shareWith = mock(ShareWith.class);
        ResourceSharing doc = mock(ResourceSharing.class);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(3);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).share(eq(RESOURCE_ID), eq(INDEX), eq(shareWith), any());

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.share(RESOURCE_ID, TYPE, shareWith, listener);

        verify(listener).onResponse(doc);
    }

    @Test
    public void testShareFailsIfNoUser() {
        ShareWith shareWith = mock(ShareWith.class);

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);

        handler.share(RESOURCE_ID, TYPE, shareWith, listener);
        verify(listener).onFailure(any(OpenSearchStatusException.class));
    }

    @Test
    public void testRevokeSuccess() {
        User user = new User("user3", ImmutableSet.of(), ImmutableSet.of(), null, ImmutableMap.of(), false);
        injectUser(user);

        ShareWith revokeTarget = mock(ShareWith.class);
        ResourceSharing doc = mock(ResourceSharing.class);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(3);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).revoke(eq(RESOURCE_ID), eq(INDEX), eq(revokeTarget), any());

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.revoke(RESOURCE_ID, TYPE, revokeTarget, listener);

        verify(listener).onResponse(doc);
    }

    @Test
    public void testRevokeFailsIfNoUser() {
        ShareWith revokeTarget = mock(ShareWith.class);

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);

        handler.revoke(RESOURCE_ID, TYPE, revokeTarget, listener);
        verify(listener).onFailure(any(OpenSearchStatusException.class));
    }

    @Test
    public void testGetSharingInfoSuccess() {
        User user = new User("user1", ImmutableSet.of(), ImmutableSet.of(), null, ImmutableMap.of(), false);
        injectUser(user);
        ResourceSharing doc = mock(ResourceSharing.class);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.getSharingInfo(RESOURCE_ID, TYPE, listener);

        verify(listener).onResponse(doc);
    }

    @Test
    public void testGetSharingInfoFailsIfNoUser() {
        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.getSharingInfo(RESOURCE_ID, TYPE, listener);

        verify(listener).onFailure(any(OpenSearchStatusException.class));
    }

    @Test
    public void testPatchSharingInfoSuccess() {
        User user = new User("user1", ImmutableSet.of(), ImmutableSet.of(), null, ImmutableMap.of(), false);
        injectUser(user);
        ShareWith add = new ShareWith(ImmutableMap.of());
        ShareWith revoke = new ShareWith(ImmutableMap.of());

        ResourceSharing doc = mock(ResourceSharing.class);
        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(4);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).patchSharingInfo(eq(RESOURCE_ID), eq(INDEX), eq(add), eq(revoke), any());

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.patchSharingInfo(RESOURCE_ID, TYPE, add, revoke, listener);

        verify(listener).onResponse(doc);
    }

    @Test
    public void testPatchSharingInfoFailsIfNoUser() {
        ShareWith x = new ShareWith(ImmutableMap.of());
        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.patchSharingInfo(RESOURCE_ID, TYPE, x, x, listener);

        verify(listener).onFailure(any(OpenSearchStatusException.class));
    }
}
