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

import java.io.IOException;
import java.nio.file.Path;

import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;

public class MyOwnAuditLog extends AuditLogSink {

	public MyOwnAuditLog(final String name, final Settings settings, final String settingsPrefix, final Path configPath, final ThreadPool threadPool,
	        final IndexNameExpressionResolver resolver, final ClusterService clusterService, AuditLogSink fallbackSink) {
        super(name, settings, settingsPrefix, fallbackSink);
    }

    @Override
	public void close() throws IOException {

	}


	public boolean doStore(AuditMessage msg) {
		return true;
	}

}
