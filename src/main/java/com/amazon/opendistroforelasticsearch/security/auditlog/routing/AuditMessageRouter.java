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

package com.amazon.opendistroforelasticsearch.security.auditlog.routing;

import java.nio.file.Path;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage.Category;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.SinkProvider;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class AuditMessageRouter {

	protected final Logger log = LogManager.getLogger(this.getClass());
	final AuditLogSink defaultSink;
	final Map<Category, List<AuditLogSink>> categorySinks = new EnumMap<>(Category.class);
	final SinkProvider sinkProvider;
	final AsyncStoragePool storagePool;
	final boolean enabled;
	boolean hasMultipleEndpoints;
	private ComplianceConfig complianceConfig;

	public AuditMessageRouter(final Settings settings, final Client clientProvider, ThreadPool threadPool, final Path configPath) {
		this.sinkProvider = new SinkProvider(settings, clientProvider, threadPool, configPath);
		this.storagePool = new AsyncStoragePool(settings);

		// get the default sink
		this.defaultSink = sinkProvider.getDefaultSink();
		if (defaultSink == null) {
			log.warn("No default storage available, audit log may not work properly. Please check configuration.");
			enabled = false;
		} else {
			// create sinks for all categories. Only do that if we have any extended setting, otherwise there is just the default category
			setupRoutes(settings);
			enabled = true;
		}
	}

	public void setComplianceConfig(ComplianceConfig complianceConfig) {
		this.complianceConfig = complianceConfig;
	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public final void route(final AuditMessage msg) {
		if (!enabled) {
			// should not happen since we check in AuditLogImpl, so this is just a safeguard
			log.error("#route(AuditMessage) called but message router is disabled");
			return;
		}
		// if we do not run the compliance features or no extended configuration is present, only log to default.
		if (!hasMultipleEndpoints || complianceConfig == null || !complianceConfig.isEnabled()) {
			store(defaultSink, msg);
		} else {
			for (AuditLogSink sink : categorySinks.get(msg.getCategory())) {
				store(sink, msg);
			}
		}
	}

	public final void close() {
		// shutdown storage pool
		storagePool.close();
		// close default
		sinkProvider.close();
	}

	protected final void close(List<AuditLogSink> sinks) {
		for (AuditLogSink sink : sinks) {
			try {
				log.info("Closing {}", sink.getClass().getSimpleName());
				sink.close();
			} catch (Exception ex) {
				log.info("Could not close delegate '{}' due to '{}'", sink.getClass().getSimpleName(), ex.getMessage());
			}
		}
	}

	private final void setupRoutes(Settings settings) {
		Map<String, Object> routesConfiguration = Utils.convertJsonToxToStructuredMap(settings.getAsSettings(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ROUTES));
		if (!routesConfiguration.isEmpty()) {
			hasMultipleEndpoints = true;
			// first set up all configured routes. We do it this way so category names are case insensitive
			// and we can warn if a non-existing category has been detected.
			for (Entry<String, Object> routesEntry : routesConfiguration.entrySet()) {
				log.trace("Setting up routes for endpoint {}, configuraton is {}", routesEntry.getKey(), routesEntry.getValue());
				String categoryName = routesEntry.getKey();
				try {
					Category category = Category.valueOf(categoryName.toUpperCase());
					// warn for duplicate definitions
					if (categorySinks.get(category) != null) {
						log.warn("Duplicate routing configuration detected for category {}, skipping.", category);
						continue;
					}
					List<AuditLogSink> sinksForCategory = createSinksForCategory(category, settings.getAsSettings(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ROUTES + "." + categoryName));
					if (!sinksForCategory.isEmpty()) {
						categorySinks.put(category, sinksForCategory);
						if(log.isTraceEnabled()) {
							log.debug("Created {} endpoints for category {}", sinksForCategory.size(), category );
						}
					} else {
						log.debug("No valid endpoints found for category {} adding only default.", category );

					}
				} catch (Exception e ) {
					log.error("Invalid category '{}' found in routing configuration. Must be one of: {}", categoryName, Category.values());
				}
			}
			// for all non-configured categories we automatically set up the default endpoint
			for(Category category : Category.values()) {
				if (!categorySinks.containsKey(category)) {
					if (log.isDebugEnabled()) {
						log.debug("No endpoint configured for category {}, adding default endpoint", category);
					}
					categorySinks.put(category, Collections.singletonList(defaultSink));
				}
			}
		}
	}

	private final List<AuditLogSink> createSinksForCategory(Category category, Settings configuration) {
		List<AuditLogSink> sinksForCategory = new LinkedList<>();
		List<String> sinks = configuration.getAsList("endpoints");
		if (sinks == null || sinks.isEmpty()) {
			log.error("No endpoints configured for category {}", category);
			return sinksForCategory;
		}
		for (String sinkName : sinks) {
			AuditLogSink sink = sinkProvider.getSink(sinkName);
			if (sink != null && !sinksForCategory.contains(sink)) {
				sinksForCategory.add(sink);
			} else {
				log.error("Configured endpoint '{}' not available", sinkName);
			}
		}
		return sinksForCategory;
	}

	private final void store(AuditLogSink sink, AuditMessage msg) {
		if (sink.isHandlingBackpressure()) {
			sink.store(msg);
			if (log.isTraceEnabled()) {
				log.trace("stored on sink {} synchronously", sink.getClass().getSimpleName());
			}
		} else {
			storagePool.submit(msg, sink);
			if (log.isTraceEnabled()) {
				log.trace("will store on sink {} asynchronously", sink.getClass().getSimpleName());
			}
		}
	}

}
