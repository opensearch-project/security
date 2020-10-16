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

package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import java.io.IOException;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;

import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.engine.Engine.Delete;
import org.elasticsearch.index.engine.Engine.DeleteResult;
import org.elasticsearch.index.engine.Engine.Index;
import org.elasticsearch.index.engine.Engine.IndexResult;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;

import com.amazon.opendistroforelasticsearch.security.auditlog.routing.AuditMessageRouter;
import org.greenrobot.eventbus.Subscribe;

public final class AuditLogImpl extends AbstractAuditLog {

	private final AuditMessageRouter messageRouter;
	private final Settings settings;
	private final boolean dlsFlsAvailable;
	private final boolean messageRouterEnabled;
	private volatile boolean enabled;
	private final Thread shutdownHook;

	public AuditLogImpl(final Settings settings,
			final Path configPath,
			final Client clientProvider,
			final ThreadPool threadPool,
			final IndexNameExpressionResolver resolver,
			final ClusterService clusterService) {
		this(settings, configPath, clientProvider, threadPool, resolver, clusterService, null, true);
	}

	public AuditLogImpl(final Settings settings,
						final Path configPath,
						final Client clientProvider,
						final ThreadPool threadPool,
						final IndexNameExpressionResolver resolver,
						final ClusterService clusterService,
						final Environment environment,
						final boolean dlsFlsAvailable) {
		super(settings, threadPool, resolver, clusterService, environment);
		this.settings = settings;
		this.dlsFlsAvailable = dlsFlsAvailable;
		if (!dlsFlsAvailable) {
			log.debug("Changes to Compliance config will ignored because DLS-FLS is not available.");
		}
		this.messageRouter = new AuditMessageRouter(settings, clientProvider, threadPool, configPath);
		this.messageRouterEnabled = this.messageRouter.isEnabled();

		log.info("Message routing enabled: {}", this.messageRouterEnabled);

		SpecialPermission.check();
		shutdownHook = AccessController.doPrivileged((PrivilegedAction<Thread>) this::addShutdownHook);
		log.debug("Shutdown hook {} registered", shutdownHook);
	}

	@Subscribe
	public void setConfig(final AuditConfig auditConfig) {
		enabled = auditConfig.isEnabled() && messageRouterEnabled;
		onAuditConfigFilterChanged(auditConfig.getFilter());
		if (dlsFlsAvailable) {
			onComplianceConfigChanged(auditConfig.getCompliance());
		}
	}

	@Override
	protected void enableRoutes() {
		if (messageRouterEnabled) {
			messageRouter.enableRoutes(settings);
		}
	}

    private Thread addShutdownHook() {
        Thread shutdownHook = new Thread(() -> messageRouter.close());
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        return shutdownHook;
    }

    private Boolean removeShutdownHook() {
        return Runtime.getRuntime().removeShutdownHook(shutdownHook);
    }

    @Override
    public void close() throws IOException {

        log.info("Closing {}", getClass().getSimpleName());

        SpecialPermission.check();
        try {
            final boolean removed = AccessController.doPrivileged((PrivilegedAction<Boolean>) this::removeShutdownHook);
            if (removed) {
                log.debug("Shutdown hook {} unregistered", shutdownHook);
                shutdownHook.run();
            } else {
                log.warn("Shutdown hook {} is not registered", shutdownHook);
            }
        } catch (IllegalStateException e) {
            log.debug("Fail to unregister shutdown hook {}. Shutdown is in progress.", shutdownHook, e);
        }
    }

	@Override
	protected void save(final AuditMessage msg) {
		if (enabled) {
			messageRouter.route(msg);
		}
	}

	@Override
	public void logFailedLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, TransportRequest request, Task task) {
		if (enabled) {
			super.logFailedLogin(effectiveUser, securityAdmin, initiatingUser, request, task);
		}
	}

	@Override
	public void logFailedLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, RestRequest request) {
		if (enabled) {
			super.logFailedLogin(effectiveUser, securityAdmin, initiatingUser, request);
		}
	}

	@Override
	public void logSucceededLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, TransportRequest request, String action, Task task) {
		if (enabled) {
			super.logSucceededLogin(effectiveUser, securityAdmin, initiatingUser, request, action, task);
		}
	}

	@Override
	public void logSucceededLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, RestRequest request) {
		if (enabled) {
			super.logSucceededLogin(effectiveUser, securityAdmin, initiatingUser, request);
		}
	}

	@Override
	public void logMissingPrivileges(String privilege, String effectiveUser, RestRequest request) {
		if (enabled) {
			super.logMissingPrivileges(privilege, effectiveUser, request);
		}
	}

	@Override
	public void logGrantedPrivileges(String effectiveUser, RestRequest request) {
		if (enabled) {
			super.logGrantedPrivileges(effectiveUser, request);
		}
	}

	@Override
	public void logMissingPrivileges(String privilege, TransportRequest request, Task task) {
		if (enabled) {
			super.logMissingPrivileges(privilege, request, task);
		}
	}

	@Override
	public void logGrantedPrivileges(String privilege, TransportRequest request, Task task) {
		if (enabled) {
			super.logGrantedPrivileges(privilege, request, task);
		}
	}

	@Override
	public void logIndexEvent(String privilege, TransportRequest request, Task task) {
		if (enabled) {
			super.logIndexEvent(privilege, request, task);
		}
	}

	@Override
	public void logBadHeaders(TransportRequest request, String action, Task task) {
		if (enabled) {
			super.logBadHeaders(request, action, task);
		}
	}

	@Override
	public void logBadHeaders(RestRequest request) {
		if (enabled) {
			super.logBadHeaders(request);
		}
	}

	@Override
	public void logSecurityIndexAttempt (TransportRequest request, String action, Task task) {
		if (enabled) {
			super.logSecurityIndexAttempt(request, action, task);
		}
	}

	@Override
	public void logSSLException(TransportRequest request, Throwable t, String action, Task task) {
		if (enabled) {
			super.logSSLException(request, t, action, task);
		}
	}

	@Override
	public void logSSLException(RestRequest request, Throwable t) {
		if (enabled) {
			super.logSSLException(request, t);
		}
	}

	@Override
	public void logDocumentRead(String index, String id, ShardId shardId, Map<String, String> fieldNameValues) {
		if (enabled) {
			super.logDocumentRead(index, id, shardId, fieldNameValues);
		}
	}

	@Override
	public void logDocumentWritten(ShardId shardId, GetResult originalResult, Index currentIndex, IndexResult result) {
		if (enabled) {
			super.logDocumentWritten(shardId, originalResult, currentIndex, result);
		}
	}

	@Override
	public void logDocumentDeleted(ShardId shardId, Delete delete, DeleteResult result) {
		if (enabled) {
			super.logDocumentDeleted(shardId, delete, result);
		}
	}

	@Override
	protected void logExternalConfig() {
		if (enabled) {
			super.logExternalConfig();
		}
	}

}
