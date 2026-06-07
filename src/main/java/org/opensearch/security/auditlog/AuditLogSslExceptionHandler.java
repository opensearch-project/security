/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportRequest;

public class AuditLogSslExceptionHandler implements SslExceptionHandler {

    private static final Logger log = LogManager.getLogger(AuditLogSslExceptionHandler.class);

    private final AuditLog auditLog;

    public AuditLogSslExceptionHandler(final AuditLog auditLog) {
        super();
        this.auditLog = auditLog;
    }

    @Override
    public void logError(Throwable t, SecurityRequestChannel request, int type) {
        switch (type) {
            case 0:
                auditLog.logSSLException(request, t);
                break;
            case 1:
                auditLog.logBadHeaders(request);
                break;
            default:
                break;
        }
    }

    @Override
    public void logError(Throwable t, boolean isRest) {
        if (isRest) {
            auditLog.logSSLException(null, t);
        } else {
            auditLog.logSSLException(null, t, null, null);
        }
    }

    @Override
    public void logError(Throwable t, TransportRequest request, String action, Task task, int type) {
        switch (type) {
            case 0:
                if (t instanceof OpenSearchException) {
                    log.debug(
                        "Exception caught at SSL request handler (action={}, class={}); not audited.",
                        action,
                        t.getClass().getName(),
                        t
                    );
                } else {
                    auditLog.logSSLException(request, t, action, task);
                }
                break;
            case 1:
                auditLog.logBadHeaders(request, action, task);
                break;
            default:
                break;
        }
    }

}
