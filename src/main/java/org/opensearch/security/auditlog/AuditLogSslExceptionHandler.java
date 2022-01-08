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
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.auditlog;

import org.opensearch.OpenSearchException;
import org.opensearch.rest.RestRequest;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportRequest;

import org.opensearch.security.ssl.SslExceptionHandler;

public class AuditLogSslExceptionHandler implements SslExceptionHandler{

    private final AuditLog auditLog;

    public AuditLogSslExceptionHandler(final AuditLog auditLog) {
        super();
        this.auditLog = auditLog;
    }

    @Override
    public void logError(Throwable t, RestRequest request, int type) {
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
            if(t instanceof OpenSearchException) {
                auditLog.logMissingPrivileges(action, request, task);
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
