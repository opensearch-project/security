/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.api.share;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.impl.AuditLogImpl;
import org.opensearch.security.resources.ResourceAccessHandler;
import org.opensearch.security.resources.sharing.ResourceSharing;
import org.opensearch.security.resources.sharing.ShareWith;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ShareTransportAction}, specifically verifying that audit events
 * are produced with the correct result field on both success and failure paths.
 */
public class ShareTransportActionTests {

    private TransportService transportService;
    private ActionFilters actionFilters;
    private ResourceAccessHandler resourceAccessHandler;
    private AuditLogImpl auditLog;
    private ThreadContext threadContext;
    private ShareTransportAction action;

    @Before
    public void setUp() {
        transportService = mock(TransportService.class);
        actionFilters = mock(ActionFilters.class);
        resourceAccessHandler = mock(ResourceAccessHandler.class);
        auditLog = mock(AuditLogImpl.class);

        ThreadPool threadPool = mock(ThreadPool.class);
        threadContext = new ThreadContext(org.opensearch.common.settings.Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(transportService.getThreadPool()).thenReturn(threadPool);

        action = new ShareTransportAction(transportService, actionFilters, resourceAccessHandler, auditLog);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void shouldAuditSuccessResultOnSuccessfulShare() {
        ShareWith shareWith = mock(ShareWith.class);
        when(shareWith.toString()).thenReturn("{users=[test_user]}");

        ShareRequest.Builder builder = new ShareRequest.Builder();
        builder.resourceId("test-resource-id");
        builder.resourceType("sample_resource");
        builder.resourceIndex(".sample_resource_sharing");
        builder.shareWith(shareWith);
        builder.method(RestRequest.Method.PUT);
        ShareRequest request = builder.build();

        ResourceSharing mockSharing = mock(ResourceSharing.class);

        // Mock ResourceAccessHandler.share() to call onResponse (success)
        doAnswer(invocation -> {
            ActionListener<ResourceSharing> listener = invocation.getArgument(3);
            listener.onResponse(mockSharing);
            return null;
        }).when(resourceAccessHandler).share(eq("test-resource-id"), eq("sample_resource"), eq(shareWith), any(ActionListener.class));

        ActionListener<ShareResponse> responseListener = mock(ActionListener.class);
        Task task = mock(Task.class);

        action.doExecute(task, request, responseListener);

        // Verify audit was called with result "success"
        verify(auditLog).logResourceSharingChanged(
            eq("test-resource-id"),
            eq("sample_resource"),
            eq("share"),
            eq("success"),
            eq(null),
            eq(null),
            eq("{users=[test_user]}"),
            eq(request),
            eq(task)
        );

        // Verify the original listener got the success response
        verify(responseListener).onResponse(any(ShareResponse.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void shouldAuditFailedResultWhenShareOperationFails() {
        ShareWith shareWith = mock(ShareWith.class);
        when(shareWith.toString()).thenReturn("{users=[test_user]}");

        ShareRequest.Builder builder = new ShareRequest.Builder();
        builder.resourceId("test-resource-id");
        builder.resourceType("sample_resource");
        builder.resourceIndex(".sample_resource_sharing");
        builder.shareWith(shareWith);
        builder.method(RestRequest.Method.PUT);
        ShareRequest request = builder.build();

        RuntimeException simulatedFailure = new RuntimeException("Index operation failed: shard unavailable");

        // Mock ResourceAccessHandler.share() to call onFailure
        doAnswer(invocation -> {
            ActionListener<ResourceSharing> listener = invocation.getArgument(3);
            listener.onFailure(simulatedFailure);
            return null;
        }).when(resourceAccessHandler).share(eq("test-resource-id"), eq("sample_resource"), eq(shareWith), any(ActionListener.class));

        ActionListener<ShareResponse> responseListener = mock(ActionListener.class);
        Task task = mock(Task.class);

        action.doExecute(task, request, responseListener);

        // Verify audit was called with result "failed"
        verify(auditLog).logResourceSharingChanged(
            eq("test-resource-id"),
            eq("sample_resource"),
            eq("share"),
            eq("failed"),
            eq(null),
            eq(null),
            eq("{users=[test_user]}"),
            eq(request),
            eq(task)
        );

        // Verify the original listener got the failure
        verify(responseListener).onFailure(simulatedFailure);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void shouldAuditFailedResultWhenPatchOperationFails() {
        ShareWith add = mock(ShareWith.class);
        when(add.toString()).thenReturn("{users=[new_user]}");

        ShareRequest.Builder builder = new ShareRequest.Builder();
        builder.resourceId("test-resource-id");
        builder.resourceType("sample_resource");
        builder.resourceIndex(".sample_resource_sharing");
        builder.add(add);
        builder.method(RestRequest.Method.PATCH);
        ShareRequest request = builder.build();

        RuntimeException simulatedFailure = new RuntimeException("No resourceIndex mapping found");

        // Mock ResourceAccessHandler.patchSharingInfo() to call onFailure
        doAnswer(invocation -> {
            ActionListener<ResourceSharing> listener = invocation.getArgument(6);
            listener.onFailure(simulatedFailure);
            return null;
        }).when(resourceAccessHandler)
            .patchSharingInfo(
                eq("test-resource-id"),
                eq("sample_resource"),
                eq(add),
                eq(null),
                eq(false),
                eq(null),
                any(ActionListener.class)
            );

        ActionListener<ShareResponse> responseListener = mock(ActionListener.class);
        Task task = mock(Task.class);

        action.doExecute(task, request, responseListener);

        // Verify audit was called with result "failed" and action "patch"
        verify(auditLog).logResourceSharingChanged(
            eq("test-resource-id"),
            eq("sample_resource"),
            eq("patch"),
            eq("failed"),
            eq("{users=[new_user]}"),
            eq(null),
            eq(null),
            eq(request),
            eq(task)
        );

        // Verify the original listener got the failure
        verify(responseListener).onFailure(simulatedFailure);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void shouldNotAuditOnGetRequest() {
        ShareRequest.Builder builder = new ShareRequest.Builder();
        builder.resourceId("test-resource-id");
        builder.resourceType("sample_resource");
        builder.resourceIndex(".sample_resource_sharing");
        builder.method(RestRequest.Method.GET);
        ShareRequest request = builder.build();

        ResourceSharing mockSharing = mock(ResourceSharing.class);

        // Mock getSharingInfo to succeed
        doAnswer(invocation -> {
            ActionListener<ResourceSharing> listener = invocation.getArgument(2);
            listener.onResponse(mockSharing);
            return null;
        }).when(resourceAccessHandler).getSharingInfo(eq("test-resource-id"), eq("sample_resource"), any(ActionListener.class));

        ActionListener<ShareResponse> responseListener = mock(ActionListener.class);
        Task task = mock(Task.class);

        action.doExecute(task, request, responseListener);

        // Verify audit was NOT called (GET is read-only)
        verify(auditLog, org.mockito.Mockito.never()).logResourceSharingChanged(
            any(),
            any(),
            any(),
            any(),
            any(),
            any(),
            any(),
            any(),
            any()
        );
    }
}
