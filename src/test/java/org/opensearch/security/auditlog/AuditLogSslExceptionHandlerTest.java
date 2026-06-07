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

package org.opensearch.security.auditlog;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuditLogSslExceptionHandler#logError(Throwable, TransportRequest, String, Task, int)}.
 *
 * The {@code type=0} branch funnels exceptions caught by the generic
 * {@code catch (Exception e)} in {@code SecuritySSLRequestHandler.messageReceived}. Privilege
 * denials are audited at their decision point (e.g. {@code SecurityFilter.handleUnauthorized})
 * before the {@link OpenSearchException} is thrown or delivered. The catch-site no longer emits a
 * {@code MISSING_PRIVILEGES} audit; it debug-logs for diagnostic visibility instead.
 */
public class AuditLogSslExceptionHandlerTest {

    private AuditLog auditLog;
    private AuditLogSslExceptionHandler handler;
    private TransportRequest request;
    private Task task;
    private static final String ACTION = "indices:data/read/search[can_match][n]";

    @Before
    public void setUp() {
        auditLog = mock(AuditLog.class);
        handler = new AuditLogSslExceptionHandler(auditLog);
        request = mock(TransportRequest.class);
        task = mock(Task.class);
    }

    @Test
    public void shouldNotEmitMissingPrivilegesForOpenSearchException() {
        Throwable t = new OpenSearchException("any opensearch exception reaching the catch site");

        handler.logError(t, request, ACTION, task, 0);

        verify(auditLog, never()).logMissingPrivileges(anyString(), any(TransportRequest.class), any(Task.class));
    }
}
