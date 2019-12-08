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

import org.elasticsearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;

public class RetrySink extends AuditLogSink{

    private static int failCount = 0;
    private static AuditMessage msg = null;

    public RetrySink(String name, Settings settings, String sinkPrefix, AuditLogSink fallbackSink) {
        super(name, settings, null, new FailingSink("", settings, "", null));
        failCount = 0;
        log.debug("init");
    }

    @Override
    protected synchronized boolean doStore(AuditMessage msg) {
        if(failCount++ < 5) {
            log.debug("Fail "+failCount);
            return false;
        }
        log.debug("doStore ok");
        RetrySink.msg = msg;
        return true;
    }

    @Override
    public boolean isHandlingBackpressure() {
        return true;
    }

    public static void init() {
        RetrySink.failCount = 0;
        msg = null;
    }

    public static AuditMessage getMsg() {
        return msg;
    }

}
