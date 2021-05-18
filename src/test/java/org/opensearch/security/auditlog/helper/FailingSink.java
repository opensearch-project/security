/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package org.opensearch.security.auditlog.helper;

import org.opensearch.common.settings.Settings;

import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;

public class FailingSink extends AuditLogSink {

    public FailingSink(String name, Settings settings, String sinkPrefix, AuditLogSink fallbackSink) {
        super(name, settings, null, fallbackSink);
    }

	@Override
	protected boolean doStore(AuditMessage msg) {
		return false;
	}

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

}
