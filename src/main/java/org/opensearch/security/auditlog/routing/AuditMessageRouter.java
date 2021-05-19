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

package org.opensearch.security.auditlog.routing;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.opensearch.security.auditlog.config.ThreadPoolConfig;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Maps;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.sink.AuditLogSink;
import org.opensearch.security.auditlog.sink.SinkProvider;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.support.ConfigConstants;

import static com.google.common.base.Preconditions.checkState;

public class AuditMessageRouter {

    protected final Logger log = LogManager.getLogger(this.getClass());
    final AuditLogSink defaultSink;
    volatile Map<AuditCategory, List<AuditLogSink>> categorySinks;
    final SinkProvider sinkProvider;
    final AsyncStoragePool storagePool;

    public AuditMessageRouter(final Settings settings, final Client clientProvider, ThreadPool threadPool, final Path configPath) {
        this(
            new SinkProvider(settings, clientProvider, threadPool, configPath),
            new AsyncStoragePool(ThreadPoolConfig.getConfig(settings))
        );
    }

    @VisibleForTesting
    public AuditMessageRouter(SinkProvider sinkProvider, AsyncStoragePool storagePool) {
        this.sinkProvider = sinkProvider;
        this.storagePool = storagePool;

        // get the default sink
        this.defaultSink = sinkProvider.getDefaultSink();
        if (defaultSink == null) {
            log.warn("No default storage available, audit log may not work properly. Please check configuration.");
        }
    }

    public boolean isEnabled() {
        return defaultSink != null;
    }

    public final void route(final AuditMessage msg) {
        if (!isEnabled()) {
            // should not happen since we check in AuditLogImpl, so this is just a safeguard
            log.error("#route(AuditMessage) called but message router is disabled");
            return;
        }
        checkState(categorySinks != null, "categorySinks is null, prior to route() call enableRoutes().");
        // if we do not run the compliance features or no extended configuration is present, only log to default.
        List<AuditLogSink> auditLogSinks = categorySinks.get(msg.getCategory());
        if (auditLogSinks == null) {
            store(defaultSink, msg);
        } else {
            auditLogSinks.stream().forEach(sink -> store(sink, msg));
        }
    }

    public final void close() {
        log.info("Closing {}", getClass().getSimpleName());
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

    public final void enableRoutes(Settings settings) {
        checkState(isEnabled(), "AuditMessageRouter is disabled");
        if (categorySinks != null) {
            return;
        }
        Map<String, Object> routesConfiguration = Utils.convertJsonToxToStructuredMap(settings.getAsSettings(ConfigConstants.SECURITY_AUDIT_CONFIG_ROUTES));
        EnumSet<AuditCategory> presentAuditCategory = EnumSet.noneOf(AuditCategory.class);
        categorySinks = routesConfiguration.entrySet().stream()
            .peek(entry -> log.trace("Setting up routes for endpoint {}, configuration is {}", entry.getKey(), entry.getValue()))
            .map(entry -> {
                String categoryName = entry.getKey();
                try {
                    // first set up all configured routes. We do it this way so category names are case insensitive
                    // and we can warn if a non-existing category has been detected.
                    AuditCategory auditCategory = AuditCategory.valueOf(categoryName.toUpperCase());
                    return Maps.immutableEntry(auditCategory, createSinksForCategory(auditCategory, (Map<String, List<String>>)entry.getValue()));
                } catch (IllegalArgumentException e) {
                    log.error("Invalid category '{}' found in routing configuration. Must be one of: {}", categoryName, AuditCategory.values());
                    return null;
                }
            })
            .filter(entry -> {
                if (entry != null) {
                    AuditCategory category = entry.getKey();
                    List<AuditLogSink> auditLogSinks = entry.getValue();
                    if (auditLogSinks.isEmpty()) {
                        log.debug("No valid endpoints found for category {}.", category);
                        return false;
                    }
                    if (presentAuditCategory.add(category)) {
                        log.debug("Created {} endpoints for category {}", auditLogSinks.size(), category);
                        return true;
                    }
                    log.warn("Duplicate routing configuration {} detected for category {}, skipping.", auditLogSinks, category);
                }
                return false;
            })
            .collect(
                Maps.toImmutableEnumMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue
                )
            );

        // for all non-configured categories we automatically set up the default endpoint
        log.warn("No endpoint configured for categories {}, using default endpoint", EnumSet.complementOf(presentAuditCategory));
    }

    private final List<AuditLogSink> createSinksForCategory(AuditCategory category, Map<String, List<String>> configuration) {
        List<AuditLogSink> sinksForCategory = new LinkedList<>();
        List<String> sinks = configuration.get("endpoints");
        if (sinks != null && !sinks.isEmpty()) {
            for (String sinkName : sinks) {
                AuditLogSink sink = sinkProvider.getSink(sinkName);
                if (sink != null && !sinksForCategory.contains(sink)) {
                    sinksForCategory.add(sink);
                } else {
                    log.error("Configured endpoint '{}' not available", sinkName);
                }
            }
        }
        if (sinksForCategory.isEmpty()) {
            log.error("No endpoints configured for category {}", category);
        }
        return sinksForCategory;
    }

    private final void store(AuditLogSink sink, AuditMessage msg) {
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (sink.isHandlingBackpressure()) {
            sink.store(msg);
            if (isTraceEnabled) {
                log.trace("stored on sink {} synchronously", sink.getClass().getSimpleName());
            }
        } else {
            storagePool.submit(msg, sink);
            if (isTraceEnabled) {
                log.trace("will store on sink {} asynchronously", sink.getClass().getSimpleName());
            }
        }
    }
}
