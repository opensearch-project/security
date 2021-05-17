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

package com.amazon.opendistroforelasticsearch.security.auditlog.sink;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class SinkProvider {

	protected final Logger log = LogManager.getLogger(this.getClass());
	private static final String FALLBACKSINK_NAME = "fallback";
	private static final String DEFAULTSINK_NAME = "default";
	private final Client clientProvider;
	private final ThreadPool threadPool;
	private final Path configPath;
	private final Settings settings;
	final Map<String, AuditLogSink> allSinks = new HashMap<>();
	AuditLogSink defaultSink;
	AuditLogSink fallbackSink;

	public SinkProvider(final Settings settings, final Client clientProvider, ThreadPool threadPool, final Path configPath) {
		this.settings = settings;
		this.clientProvider = clientProvider;
		this.threadPool = threadPool;
		this.configPath = configPath;

		// fall back sink, make sure we don't lose messages
		String fallbackConfigPrefix = ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS + "." + FALLBACKSINK_NAME;
		Settings fallbackSinkSettings = settings.getAsSettings(fallbackConfigPrefix);
		if(!fallbackSinkSettings.isEmpty()) {
			this.fallbackSink = createSink(FALLBACKSINK_NAME, fallbackSinkSettings.get("type"), settings, fallbackConfigPrefix+".config");
		}

		// make sure we always have a fallback to write to
		if (this.fallbackSink == null) {
			this.fallbackSink = new DebugSink(FALLBACKSINK_NAME, settings, null);
		}

		allSinks.put(FALLBACKSINK_NAME, this.fallbackSink);

		// create default sink
		defaultSink = this.createSink(DEFAULTSINK_NAME, settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT), settings, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT);
		if (defaultSink == null) {
			log.error("Default endpoint could not be created, auditlog will not work properly.");
			return;
		}

		allSinks.put(DEFAULTSINK_NAME, defaultSink);

		// create all other sinks
		Map<String, Object> sinkSettingsMap = Utils.convertJsonToxToStructuredMap(settings.getAsSettings(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS));

		for (Entry<String, Object> sinkEntry : sinkSettingsMap.entrySet()) {
			String sinkName = sinkEntry.getKey();
			// do not create fallback twice
			if(sinkName.equalsIgnoreCase(FALLBACKSINK_NAME)) {
				continue;
			}
			String type = settings.getAsSettings(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS + "." + sinkName).get("type");
			if (type == null) {
				log.error("No type defined for endpoint {}.", sinkName);
				continue;
			}
			AuditLogSink sink = createSink(sinkName, type, this.settings, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS + "." + sinkName + ".config");
			if (sink == null) {
				log.error("Endpoint '{}' could not be created, check log file for further information.", sinkName);
				continue;
			}
			allSinks.put(sinkName.toLowerCase(), sink);
			if (log.isDebugEnabled()) {
				log.debug("sink '{}' created successfully.", sinkName);
			}
		}
	}

	public AuditLogSink getSink(String sinkName) {
		return allSinks.get(sinkName.toLowerCase());
	}

	public AuditLogSink getDefaultSink() {
		return defaultSink;
	}

	public void close() {
		for (AuditLogSink sink : allSinks.values()) {
			close(sink);
		}
	}

	protected void close(AuditLogSink sink) {
		try {
			log.info("Closing {}", sink.getClass().getSimpleName());
			sink.close();
		} catch (Exception ex) {
			log.info("Could not close sink '{}' due to '{}'", sink.getClass().getSimpleName(), ex.getMessage());
		}
	}

	private final AuditLogSink createSink(final String name, final String type, final Settings settings, final String settingsPrefix) {
		AuditLogSink sink = null;
		if (type != null) {
			switch (type.toLowerCase()) {
			case "internal_opensearch":
				sink = new InternalOpenSearchSink(name, settings, settingsPrefix, configPath, clientProvider, threadPool, fallbackSink);
				break;
			case "external_opensearch":
				try {
					sink = new ExternalOpenSearchSink(name, settings, settingsPrefix, configPath, fallbackSink);
				} catch (Exception e) {
					log.error("Audit logging unavailable: Unable to setup HttpOpenSearchAuditLog due to", e);
				}
				break;
			case "webhook":
				try {
					sink = new WebhookSink(name, settings, settingsPrefix, configPath, fallbackSink);
				} catch (Exception e1) {
					log.error("Audit logging unavailable: Unable to setup WebhookAuditLog due to", e1);
				}
				break;
			case "debug":
				sink = new DebugSink(name, settings, fallbackSink);
				break;
            case "noop":
                sink = new NoopSink(name, settings, fallbackSink);
                break;
			case "log4j":
				sink = new Log4JSink(name, settings, settingsPrefix, fallbackSink);
				break;
			case "kafka":
				sink = new KafkaSink(name, settings, settingsPrefix, fallbackSink);
				break;
			default:
				try {
					Class<?> delegateClass = Class.forName(type);
					if (AuditLogSink.class.isAssignableFrom(delegateClass)) {
						try {
							sink = (AuditLogSink) delegateClass.getConstructor(String.class, Settings.class, String.class, Path.class, Client.class, ThreadPool.class, AuditLogSink.class).newInstance(name, settings, settingsPrefix, configPath,
									clientProvider, threadPool, fallbackSink);
						} catch (Throwable e) {
							sink = (AuditLogSink) delegateClass.getConstructor(String.class, Settings.class, String.class, AuditLogSink.class).newInstance(name, settings, settingsPrefix, fallbackSink);
						}
					} else {
						log.error("Audit logging unavailable: '{}' is not a subclass of {}", type, AuditLogSink.class.getSimpleName());
					}
				} catch (Throwable e) { // we need really catch a Throwable here!
					log.error("Audit logging unavailable: Cannot instantiate object of class {} due to ", type, e);
				}
			}
		}
		return sink;
	}

}
