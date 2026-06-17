/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.tasks.Task;

/**
 * A lightweight action filter that logs audit events without performing
 * authentication or authorization. Used in SSL-only and disabled modes
 * where the full SecurityFilter is not registered.
 */
public class AuditActionFilter implements ActionFilter {

    private final AuditLog auditLog;

    public AuditActionFilter(AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
        Task task,
        String action,
        Request request,
        ActionRequestMetadata<Request, Response> actionRequestMetadata,
        ActionListener<Response> listener,
        ActionFilterChain<Request, Response> chain
    ) {
        auditLog.logGrantedPrivileges(action, request, task);
        auditLog.logIndexEvent(action, request, task);
        chain.proceed(task, action, request, listener);
    }
}
