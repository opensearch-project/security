/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.auditlog.sink;

import org.opensearch.common.settings.Settings;

import org.opensearch.security.auditlog.impl.AuditMessage;

public final class DebugSink extends AuditLogSink {

    public DebugSink(String name, Settings settings, AuditLogSink fallbackSink) {
        super(name, settings, null, fallbackSink);
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

    @Override
    public boolean doStore(final AuditMessage msg) {
        System.out.println("AUDIT_LOG: " + msg.toPrettyString());
        return true;
    }

}
