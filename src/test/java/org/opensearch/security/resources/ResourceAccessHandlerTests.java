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
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.ShareWith;
import org.opensearch.security.securityconf.FlattenedActionGroups;
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
public class ResourceAccessHandlerTests {

    @Mock
    private ThreadPool threadPool;
    @Mock
    private ResourceSharingIndexHandler sharingIndexHandler;
    @Mock
    private AdminDNs adminDNs;

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
        handler = new ResourceAccessHandler(threadPool, sharingIndexHandler, adminDNs, resourcePluginInfo);

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
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(true);
    }

    @Test
    public void testHasPermission_ownerAllowed() {
        User user = new User("alice", ImmutableSet.of("r1"), ImmutableSet.of("b1"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.isCreatedBy("alice")).thenReturn(true);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(true);
    }

    @Test
    public void testHasPermission_sharedWithUserAllowed() {
        User user = new User("bob", ImmutableSet.of("role1"), ImmutableSet.of("backend1"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        // Document setup: shared with the user at access-level "read"
        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.getAccessLevelsForUser(user)).thenReturn(Set.of("read"));

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
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(true);
    }

    @Test
    public void testHasPermission_noAccessLevelsDenied() {
        User user = new User("charlie", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(false);
    }

    @Test
    public void testHasPermission_grantedViaWorkspaceMembership() {
        // Resource itself grants the user nothing, but it belongs to workspace "ws-1" and the user has
        // "read" access on that workspace's own sharing record -> access is inherited from the workspace container.
        User user = new User("erin", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        final String workspaceIndex = "workspace-index";
        final String workspaceId = "ws-1";
        when(resourcePluginInfo.indexByType("workspace")).thenReturn(workspaceIndex);

        // The resource: no direct access, belongs to ws-1, not created by the user.
        ResourceSharing resourceDoc = mock(ResourceSharing.class);
        when(resourceDoc.isCreatedBy("erin")).thenReturn(false);
        when(resourceDoc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());
        when(resourceDoc.getWorkspaces()).thenReturn(Set.of(workspaceId));

        // The workspace record: shares "read" with the user.
        ResourceSharing workspaceDoc = mock(ResourceSharing.class);
        when(workspaceDoc.isCreatedBy("erin")).thenReturn(false);
        when(workspaceDoc.getAccessLevelsForUser(user)).thenReturn(Set.of("read"));

        FlattenedActionGroups ag = mock(FlattenedActionGroups.class);
        when(resourcePluginInfo.flattenedForType("workspace")).thenReturn(ag);
        when(ag.resolve(any())).thenReturn(ImmutableSet.of("read"));

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(resourceDoc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        // Workspaces are resolved in a single batched mget, not per-workspace GETs.
        doAnswer(inv -> {
            ActionListener<java.util.Map<String, ResourceSharing>> l = inv.getArgument(2);
            l.onResponse(java.util.Map.of(workspaceId, workspaceDoc));
            return null;
        }).when(sharingIndexHandler).fetchSharingInfoForIds(eq(workspaceIndex), any(), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(true);
    }

    @Test
    public void testHasPermission_deniedWhenNoWorkspaceGrantsAccess() {
        // Resource grants nothing and belongs to a workspace the user has no access on -> denied.
        User user = new User("frank", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        final String workspaceIndex = "workspace-index";
        final String workspaceId = "ws-9";
        when(resourcePluginInfo.indexByType("workspace")).thenReturn(workspaceIndex);

        ResourceSharing resourceDoc = mock(ResourceSharing.class);
        when(resourceDoc.isCreatedBy("frank")).thenReturn(false);
        when(resourceDoc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());
        when(resourceDoc.getParentId()).thenReturn(null);
        when(resourceDoc.getWorkspaces()).thenReturn(Set.of(workspaceId));

        ResourceSharing workspaceDoc = mock(ResourceSharing.class);
        when(workspaceDoc.isCreatedBy("frank")).thenReturn(false);
        when(workspaceDoc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(resourceDoc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        doAnswer(inv -> {
            ActionListener<java.util.Map<String, ResourceSharing>> l = inv.getArgument(2);
            l.onResponse(java.util.Map.of(workspaceId, workspaceDoc));
            return null;
        }).when(sharingIndexHandler).fetchSharingInfoForIds(eq(workspaceIndex), any(), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(false);
    }

    @Test
    public void testHasPermission_containerCycleTerminatesAndDenies() {
        // Malformed graph: the resource belongs to workspace "ws-loop", whose own record (incorrectly) lists
        // itself as one of its workspaces. Without the visited-set guard this would recurse forever. With it,
        // the walk terminates and denies (no container actually grants access).
        User user = new User("gwen", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        final String workspaceIndex = "workspace-index";
        final String loopWs = "ws-loop";
        when(resourcePluginInfo.indexByType("workspace")).thenReturn(workspaceIndex);

        // Resource: no direct access, belongs to ws-loop.
        ResourceSharing resourceDoc = mock(ResourceSharing.class);
        when(resourceDoc.isCreatedBy("gwen")).thenReturn(false);
        when(resourceDoc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());
        when(resourceDoc.getParentId()).thenReturn(null);
        when(resourceDoc.getWorkspaces()).thenReturn(Set.of(loopWs));

        // Workspace ws-loop: grants nothing and (malformed) contains itself.
        ResourceSharing loopDoc = mock(ResourceSharing.class);
        when(loopDoc.isCreatedBy("gwen")).thenReturn(false);
        when(loopDoc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(resourceDoc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        doAnswer(inv -> {
            ActionListener<java.util.Map<String, ResourceSharing>> l = inv.getArgument(2);
            l.onResponse(java.util.Map.of(loopWs, loopDoc));
            return null;
        }).when(sharingIndexHandler).fetchSharingInfoForIds(eq(workspaceIndex), any(), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        // Must terminate (no StackOverflow / infinite loop) and deny.
        verify(listener).onResponse(false);
    }

    @Test
    public void testHasPermission_nullDocumentDenied() {
        User user = new User("dave", ImmutableSet.of("x"), ImmutableSet.of("y"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(null);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

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
            ActionListener<ResourceSharing> l = inv.getArgument(6);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).patchSharingInfo(eq(RESOURCE_ID), eq(INDEX), eq(add), eq(revoke), eq(false), eq(null), any());

        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.patchSharingInfo(RESOURCE_ID, TYPE, add, revoke, false, null, listener);

        verify(listener).onResponse(doc);
    }

    @Test
    public void testPatchSharingInfoFailsIfNoUser() {
        ShareWith x = new ShareWith(ImmutableMap.of());
        ActionListener<ResourceSharing> listener = mock(ActionListener.class);
        handler.patchSharingInfo(RESOURCE_ID, TYPE, x, x, false, null, listener);

        verify(listener).onFailure(any(OpenSearchStatusException.class));
    }
}
