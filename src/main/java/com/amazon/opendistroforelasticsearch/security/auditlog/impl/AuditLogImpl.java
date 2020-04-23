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
import java.util.concurrent.atomic.AtomicBoolean;

import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.AuditModel;
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
	private final boolean enabled;
	private final boolean dlsFlsAvailable;
	private final Environment environment;
	private AtomicBoolean externalConfigLogged = new AtomicBoolean();

	public AuditLogImpl(final Settings settings,
						final Path configPath,
						final Client clientProvider,
						final ThreadPool threadPool,
						final IndexNameExpressionResolver resolver,
						final ClusterService clusterService,
						final boolean dlsFlsAvailable,
						final Environment environment) {
		super(settings, threadPool, resolver, clusterService, dlsFlsAvailable);
		this.environment = environment;
		this.messageRouter = new AuditMessageRouter(settings, clientProvider, threadPool, configPath);
		this.enabled = messageRouter.isEnabled();
		this.dlsFlsAvailable = dlsFlsAvailable;

		log.info("Message routing enabled: {}", this.enabled);

		final SecurityManager sm = System.getSecurityManager();

		if (sm != null) {
			log.debug("Security Manager present");
			sm.checkPermission(new SpecialPermission());
		}

		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			@Override
			public Object run() {
				Runtime.getRuntime().addShutdownHook(new Thread() {

					@Override
					public void run() {
						try {
							close();
						} catch (final IOException e) {
							log.warn("Exception while shutting down message router", e);
						}
					}
				});
				log.debug("Shutdown Hook registered");
				return null;
			}
		});

	}

	@Subscribe
    public void onAuditModelChanged(final AuditModel auditModel) {
	    this.auditConfigFilter = AuditConfig.Filter.from(auditModel);
        this.auditConfigFilter.log(log);

		if (dlsFlsAvailable) {
			this.complianceConfig = ComplianceConfig.from(auditModel, settings);
			this.messageRouter.enableRoutes();
			this.complianceConfig.log(log);
			logExternalConfigIfNeeded();
		} else {
			this.complianceConfig = null;
			this.messageRouter.disableRoutes();
			log.debug("Compliance config is null because DLS-FLS is not available.");
		}
    }

    private void logExternalConfigIfNeeded() {
		final ComplianceConfig complianceConfig = getComplianceConfig();
		if (complianceConfig != null && complianceConfig.isEnabled() && complianceConfig.shouldLogExternalConfig() && !externalConfigLogged.getAndSet(true)) {
			log.info("logging external config");
			logExternalConfig(settings, environment);
		}
	}

    public boolean isEnabled() {
		return this.enabled && this.auditConfigFilter != null;
	}

	@Override
	public void close() throws IOException {
		messageRouter.close();
	}

	@Override
	protected void save(final AuditMessage msg) {
		if (isEnabled()) {
			messageRouter.route(msg);
		}
	}

	@Override
	public void logFailedLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, TransportRequest request, Task task) {
		if (isEnabled()) {
			super.logFailedLogin(effectiveUser, securityAdmin, initiatingUser, request, task);
		}
	}

	@Override
	public void logFailedLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, RestRequest request) {
		if (isEnabled()) {
			super.logFailedLogin(effectiveUser, securityAdmin, initiatingUser, request);
		}
	}

	@Override
	public void logSucceededLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, TransportRequest request, String action, Task task) {
		if (isEnabled()) {
			super.logSucceededLogin(effectiveUser, securityAdmin, initiatingUser, request, action, task);
		}
	}

	@Override
	public void logSucceededLogin(String effectiveUser, boolean securityAdmin, String initiatingUser, RestRequest request) {
		if (isEnabled()) {
			super.logSucceededLogin(effectiveUser, securityAdmin, initiatingUser, request);
		}
	}

	@Override
	public void logMissingPrivileges(String privilege, String effectiveUser, RestRequest request) {
		if (isEnabled()) {
			super.logMissingPrivileges(privilege, effectiveUser, request);
		}
	}

	@Override
	public void logMissingPrivileges(String privilege, TransportRequest request, Task task) {
		if (isEnabled()) {
			super.logMissingPrivileges(privilege, request, task);
		}
	}

	@Override
	public void logGrantedPrivileges(String privilege, TransportRequest request, Task task) {
		if (isEnabled()) {
			super.logGrantedPrivileges(privilege, request, task);
		}
	}

	@Override
	public void logBadHeaders(TransportRequest request, String action, Task task) {
		if (isEnabled()) {
			super.logBadHeaders(request, action, task);
		}
	}

	@Override
	public void logBadHeaders(RestRequest request) {
		if (isEnabled()) {
			super.logBadHeaders(request);
		}
	}

	@Override
	public void logSecurityIndexAttempt (TransportRequest request, String action, Task task) {
		if (isEnabled()) {
			super.logSecurityIndexAttempt(request, action, task);
		}
	}

	@Override
	public void logSSLException(TransportRequest request, Throwable t, String action, Task task) {
		if (isEnabled()) {
			super.logSSLException(request, t, action, task);
		}
	}

	@Override
	public void logSSLException(RestRequest request, Throwable t) {
		if (isEnabled()) {
			super.logSSLException(request, t);
		}
	}

	@Override
	public void logDocumentRead(String index, String id, ShardId shardId, Map<String, String> fieldNameValues) {
		if (isEnabled()) {
			super.logDocumentRead(index, id, shardId, fieldNameValues);
		}
	}

	@Override
	public void logDocumentWritten(ShardId shardId, GetResult originalResult, Index currentIndex, IndexResult result) {
		if (isEnabled()) {
			super.logDocumentWritten(shardId, originalResult, currentIndex, result);
		}
	}

	@Override
	public void logDocumentDeleted(ShardId shardId, Delete delete, DeleteResult result) {
		if (isEnabled()) {
			super.logDocumentDeleted(shardId, delete, result);
		}
	}

	@Override
	public void logExternalConfig(Settings settings, Environment environment) {
		if (isEnabled()) {
			super.logExternalConfig(settings, environment);
		}
	}

}
