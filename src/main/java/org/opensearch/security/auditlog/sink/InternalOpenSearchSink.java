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

package org.opensearch.security.auditlog.sink;

import java.io.IOException;
import java.nio.file.Path;

import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext.StoredContext;
import org.opensearch.threadpool.ThreadPool;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HeaderHelper;

public final class InternalOpenSearchSink extends AuditLogSink {

	private final Client clientProvider;
	final String index;
	final String type;
	private DateTimeFormatter indexPattern;
	private final ThreadPool threadPool;

	public InternalOpenSearchSink(final String name, final Settings settings, final String settingsPrefix, final Path configPath, final Client clientProvider, ThreadPool threadPool, AuditLogSink fallbackSink) {
		super(name, settings, settingsPrefix, fallbackSink);
		this.clientProvider = clientProvider;
		Settings sinkSettings = getSinkSettings(settingsPrefix);

		this.index = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_OPENSEARCH_INDEX, "'security-auditlog-'YYYY.MM.dd");
		this.type = sinkSettings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_OPENSEARCH_TYPE, null);

		this.threadPool = threadPool;
		try {
			this.indexPattern = DateTimeFormat.forPattern(index);
		} catch (IllegalArgumentException e) {
			log.debug("Unable to parse index pattern due to {}. " + "If you have no date pattern configured you can safely ignore this message", e.getMessage());
		}
	}

	@Override
	public void close() throws IOException {

	}

	public boolean doStore(final AuditMessage msg) {

		if (Boolean.parseBoolean((String) HeaderHelper.getSafeFromHeader(threadPool.getThreadContext(), ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER))) {
			if (log.isTraceEnabled()) {
				log.trace("audit log of audit log will not be executed");
			}
			return true;
		}

		try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {
			try {
				final IndexRequestBuilder irb = clientProvider.prepareIndex(getExpandedIndexName(indexPattern, index), type).setRefreshPolicy(RefreshPolicy.IMMEDIATE).setSource(msg.getAsMap());
				threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
				irb.setTimeout(TimeValue.timeValueMinutes(1));
				irb.execute().actionGet();
				return true;
			} catch (final Exception e) {
				log.error("Unable to index audit log {} due to", msg, e);
				return false;
			}
		}
	}
}
