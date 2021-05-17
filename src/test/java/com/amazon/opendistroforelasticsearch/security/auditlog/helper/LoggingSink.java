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

package com.amazon.opendistroforelasticsearch.security.auditlog.helper;

import java.util.ArrayList;
import java.util.List;

import org.opensearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;

public class LoggingSink extends AuditLogSink {

	public List<AuditMessage> messages = new ArrayList<AuditMessage>(100);
    public StringBuffer sb = new StringBuffer();

    public LoggingSink(String name, Settings settings, String settingsPrefix, AuditLogSink fallbackSink) {
        super(name, settings, null, fallbackSink);
    }


    public boolean doStore(AuditMessage msg) {
        sb.append(msg.toPrettyString()+System.lineSeparator());
        messages.add(msg);
        return true;
    }

    public synchronized void clear() {
        sb.setLength(0);
        messages.clear();
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

}
