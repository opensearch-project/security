/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.util.Collections;
import java.util.List;
import java.util.Map;
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
import org.opensearch.core.rest.RestStatus;
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
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
        threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, user);
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
    public void testHasPermission_dissociatedResourceLosesWorkspaceGrant() {
        // A workspace record exists that WOULD grant the action, but the resource has been dissociated from it: its
        // own workspace set is empty. checkContainers must not fan out to any workspace, so access is denied. This is
        // the write-path half of associate/dissociate consistency -- a stale membership would leak authorization.
        User user = new User("heidi", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        // The resource: no direct access, no parent, and NO workspaces (dissociated).
        ResourceSharing resourceDoc = mock(ResourceSharing.class);
        when(resourceDoc.isCreatedBy("heidi")).thenReturn(false);
        when(resourceDoc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());
        when(resourceDoc.getParentId()).thenReturn(null);
        when(resourceDoc.getWorkspaces()).thenReturn(Collections.emptySet());

        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(resourceDoc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(false);
        // With no workspaces on the resource, the workspace index is never queried.
        verify(sharingIndexHandler, never()).fetchSharingInfoForIds(any(), any(), any());
    }

    @Test
    public void testHasPermission_workspaceIsLeafEvaluatedNoRecursion() {
        // Workspaces are evaluated as leaves (their own share_with) and never recursed into, so even a malformed
        // self-referential workspace terminates: the resource belongs to "ws-loop" which grants nothing, so access
        // is denied without following ws-loop's own workspaces.
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
    public void testHasPermission_parentCycleTerminates() {
        // Two resources of the same type naming each other as parent. checkParent recurses through hasPermission, so a
        // cycle in the parent chain never reaches a terminating case.
        User user = new User("ivy", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        stubRecord("res-a", parentOf("res-b", user));
        stubRecord("res-b", parentOf("res-a", user));

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission("res-a", TYPE, ACTION, listener);

        verify(listener).onResponse(false);
        // Each record in the cycle is read once: the walk stops at the first one it is asked to consult twice
        verify(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq("res-a"), any());
        verify(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq("res-b"), any());
    }

    @Test
    public void testHasPermission_selfParentTerminates() {
        // A record naming itself as its own parent, which a provider declaring its own type as its parent type makes
        // reachable from document data alone.
        User user = new User("jude", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        stubRecord(RESOURCE_ID, parentOf(RESOURCE_ID, user));

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(RESOURCE_ID, TYPE, ACTION, listener);

        verify(listener).onResponse(false);
        // The record naming itself is read once, not again as its own parent
        verify(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());
    }

    @Test
    public void testHasPermission_grandparentStillGrantsAccess() {
        // Ending the walk at a repeated record must not shorten a chain that does terminate: the grandparent is the
        // record that grants the action, two hops up.
        User user = new User("kira", ImmutableSet.of("roleA"), ImmutableSet.of("backendA"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        ResourceSharing grandparent = mock(ResourceSharing.class);
        when(grandparent.isCreatedBy("kira")).thenReturn(true);

        stubRecord("child", parentOf("parent", user));
        stubRecord("parent", parentOf("grandparent", user));
        stubRecord("grandparent", grandparent);

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission("child", TYPE, ACTION, listener);

        verify(listener).onResponse(true);
    }

    /** A record that grants {@code user} nothing and names {@code parentId} as its parent, of the same type. */
    private ResourceSharing parentOf(String parentId, User user) {
        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.isCreatedBy(user.getName())).thenReturn(false);
        when(doc.getAccessLevelsForUser(user)).thenReturn(Collections.emptySet());
        when(doc.getWorkspaces()).thenReturn(Collections.emptySet());
        when(doc.getParentId()).thenReturn(parentId);
        when(doc.getParentType()).thenReturn(TYPE);
        return doc;
    }

    private void stubRecord(String resourceId, ResourceSharing record) {
        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(record);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(resourceId), any());
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
    public void testHasPermission_multipleIds_allowedWhenEveryRecordGrantsAction() {
        User user = new User("erin", ImmutableSet.of("x"), ImmutableSet.of("y"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        // Several ids are read in one mget rather than a GET each
        stubSharingInfoForIds(Map.of("res-1", ownedBy(user), "res-2", ownedBy(user)));

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(List.of("res-1", "res-2"), TYPE, ACTION, listener);

        verify(listener).onResponse(true);
        verify(sharingIndexHandler, never()).fetchSharingInfo(any(), any(), any());
    }

    @Test
    public void testHasPermission_multipleIds_deniedWhenOneIdHasNoRecord() {
        User user = new User("frank", ImmutableSet.of("x"), ImmutableSet.of("y"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        // res-2 is absent from the mget response, so nothing grants it
        stubSharingInfoForIds(Map.of("res-1", ownedBy(user)));

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(List.of("res-1", "res-2"), TYPE, ACTION, listener);

        verify(listener).onResponse(false);
    }

    /**
     * An id whose own record does not grant the action falls back to its containers, exactly as it does on the single-id
     * path. Here the container check denies, so the request as a whole is denied.
     */
    @Test
    public void testHasPermission_multipleIds_deniedWhenContainerFallbackDenies() {
        User user = new User("grace", ImmutableSet.of("x"), ImmutableSet.of("y"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        ResourceSharing grantsNothing = mock(ResourceSharing.class);
        when(grantsNothing.isCreatedBy(user.getName())).thenReturn(false);
        when(grantsNothing.getAccessLevelsForUser(user)).thenReturn(Set.of());
        stubSharingInfoForIds(Map.of("res-1", ownedBy(user), "res-2", grantsNothing));

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(List.of("res-1", "res-2"), TYPE, ACTION, listener);

        verify(listener).onResponse(false);
    }

    @Test
    public void testHasPermission_multipleIds_deniedWhenTheReadFails() {
        User user = new User("heidi", ImmutableSet.of("x"), ImmutableSet.of("y"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        doAnswer(inv -> {
            ActionListener<Map<String, ResourceSharing>> l = inv.getArgument(2);
            l.onFailure(new OpenSearchStatusException("boom", RestStatus.INTERNAL_SERVER_ERROR));
            return null;
        }).when(sharingIndexHandler).fetchSharingInfoForIds(eq(INDEX), any(), any());

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(List.of("res-1", "res-2"), TYPE, ACTION, listener);

        // Reported as a failure rather than a silent allow; the evaluator turns it into a denial
        verify(listener).onFailure(any(OpenSearchStatusException.class));
        verify(listener, never()).onResponse(anyBoolean());
    }

    /**
     * One id is the common case, and the single-id path already owns the whole evaluation, so the collection overload
     * delegates to it rather than paying for an mget.
     */
    @Test
    public void testHasPermission_singleIdCollection_delegatesToTheSingleIdPath() {
        User user = new User("ivan", ImmutableSet.of("x"), ImmutableSet.of("y"), null, ImmutableMap.of(), false);
        injectUser(user);
        when(adminDNs.isAdmin(user)).thenReturn(false);

        stubOwnedBy(user, RESOURCE_ID);

        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(List.of(RESOURCE_ID, RESOURCE_ID), TYPE, ACTION, listener);

        verify(listener).onResponse(true);
        verify(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(RESOURCE_ID), any());
        verify(sharingIndexHandler, never()).fetchSharingInfoForIds(any(), any(), any());
    }

    @Test
    public void testHasPermission_multipleIds_deniedWhenNoIdGiven() {
        ActionListener<Boolean> listener = mock(ActionListener.class);
        handler.hasPermission(Collections.emptyList(), TYPE, ACTION, listener);

        verify(listener).onResponse(false);
        verify(sharingIndexHandler, never()).fetchSharingInfo(any(), any(), any());
        verify(sharingIndexHandler, never()).fetchSharingInfoForIds(any(), any(), any());
    }

    private ResourceSharing ownedBy(User user) {
        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.isCreatedBy(user.getName())).thenReturn(true);
        return doc;
    }

    private void stubSharingInfoForIds(Map<String, ResourceSharing> recordsById) {
        doAnswer(inv -> {
            ActionListener<Map<String, ResourceSharing>> l = inv.getArgument(2);
            l.onResponse(recordsById);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfoForIds(eq(INDEX), any(), any());
    }

    /**
     * Makes the sharing record of {@code resourceId} report {@code user} as its creator, which grants every action.
     */
    private void stubOwnedBy(User user, String resourceId) {
        ResourceSharing doc = mock(ResourceSharing.class);
        when(doc.isCreatedBy(user.getName())).thenReturn(true);
        doAnswer(inv -> {
            ActionListener<ResourceSharing> l = inv.getArgument(2);
            l.onResponse(doc);
            return null;
        }).when(sharingIndexHandler).fetchSharingInfo(eq(INDEX), eq(resourceId), any());
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
