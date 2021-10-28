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

package org.opensearch.security.auditlog.helper;

import java.io.IOException;
import java.nio.file.Path;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.threadpool.ThreadPool;

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
