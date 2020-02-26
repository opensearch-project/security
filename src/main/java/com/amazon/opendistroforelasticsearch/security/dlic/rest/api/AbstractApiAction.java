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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateAction;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateNodeResponse;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator.ErrorType;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigFactory;
import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.amazon.opendistroforelasticsearch.security.securityconf.StaticDefinable;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;

public abstract class AbstractApiAction extends BaseRestHandler {

	protected final Logger log = LogManager.getLogger(this.getClass());

	protected final ConfigurationRepository cl;
	protected final ClusterService cs;
	final ThreadPool threadPool;
	private String opendistroIndex;
	private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
	protected final AuditLog auditLog;
	protected final Settings settings;
	private AdminDNs adminDNs;

	protected AbstractApiAction(final Settings settings, final Path configPath, final RestController controller,
								final Client client, final AdminDNs adminDNs, final ConfigurationRepository cl,
								final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
								ThreadPool threadPool, AuditLog auditLog) {
		super();
		this.settings = settings;
		this.opendistroIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME,
				ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);

		this.adminDNs = adminDNs;
		this.cl = cl;
		this.cs = cs;
		this.threadPool = threadPool;
		this.restApiPrivilegesEvaluator = new RestApiPrivilegesEvaluator(settings, adminDNs, evaluator,
				principalExtractor, configPath, threadPool);
		this.auditLog = auditLog;
		this.registerHandlers(controller, settings);
	}

	/**
	 * Abstract function to register handlers for API actions
	 * @param controller rest controller
	 * @param settings settings configuration
	 */
	protected abstract void registerHandlers(RestController controller, Settings settings);

	protected abstract AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params);

	protected abstract String getResourceName();

	protected abstract CType getConfigName();

	protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {

		try {
			// validate additional settings, if any
			AbstractConfigurationValidator validator = getValidator(request, request.content());
			if (!validator.validate()) {
				request.params().clear();
				badRequestResponse(channel, validator);
				return;
			}
			switch (request.method()) {
				case DELETE:
					handleDelete(channel,request, client, validator.getContentAsNode()); break;
				case POST:
					handlePost(channel,request, client, validator.getContentAsNode());break;
				case PUT:
					handlePut(channel,request, client, validator.getContentAsNode());break;
				case GET:
					handleGet(channel,request, client, validator.getContentAsNode());break;
				default:
					throw new IllegalArgumentException(request.method() + " not supported");
			}
		} catch (JsonMappingException jme) {
			throw jme;
			//TODO strip source
			//if(jme.getLocation() == null || jme.getLocation().getSourceRef() == null) {
			//    throw jme;
			//} else throw new JsonMappingException(null, jme.getMessage());
		}
	}

	protected void handleDelete(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);

		if (isHidden(existingConfiguration, name)) {
			notFound(channel, getResourceName() + " " + name + " not found.");
			return;
		}

		if (isReservedAndAccessible(existingConfiguration, name)) {
			forbidden(channel, "Resource '"+ name +"' is read-only.");
			return;
		}

		boolean existed = existingConfiguration.exists(name);
		existingConfiguration.remove(name);

		if (existed) {
			saveAnUpdateConfigs(client, request, getConfigName(), existingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

				@Override
				public void onResponse(IndexResponse response) {
					successResponse(channel, "'" + name + "' deleted.");
				}
			});

		} else {
			notFound(channel, getResourceName() + " " + name + " not found.");
		}
	}

	protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {

		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);

		if (isHidden(existingConfiguration, name)) {
			forbidden(channel, "Resource '"+ name +"' is not available.");
			return;
		}

		if (isReservedAndAccessible(existingConfiguration, name)) {
			forbidden(channel, "Resource '"+ name +"' is read-only.");
			return;
		}

		if (log.isTraceEnabled() && content != null) {
			log.trace(content.toString());
		}

		boolean existed = existingConfiguration.exists(name);
		existingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, existingConfiguration.getImplementingClass()));

		saveAnUpdateConfigs(client, request, getConfigName(), existingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

			@Override
			public void onResponse(IndexResponse response) {
				if (existed) {
					successResponse(channel, "'" + name + "' updated.");
				} else {
					createdResponse(channel, "'" + name + "' created.");
				}

			}
		});

	}

	protected void handlePost(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		notImplemented(channel, Method.POST);
	}

	protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content)
			throws IOException{

		final String resourcename = request.param("name");

		final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);
		filter(configuration);


		// no specific resource requested, return complete config
		if (resourcename == null || resourcename.length() == 0) {

			successResponse(channel, configuration);
			return;
		}

		if (!configuration.exists(resourcename)) {
			notFound(channel, "Resource '" + resourcename + "' not found.");
			return;
		}

		configuration.removeOthers(resourcename);
		successResponse(channel, configuration);

		return;
	}

	protected final SecurityDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
		SecurityDynamicConfiguration<?> loaded = cl.getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent).get(config).deepClone();
		return DynamicConfigFactory.addStatics(loaded);
	}

	protected boolean ensureIndexExists() {
		if (!cs.state().metaData().hasConcreteIndex(this.opendistroIndex)) {
			return false;
		}
		return true;
	}

	protected void filter(SecurityDynamicConfiguration<?> builder) {
		builder.removeHidden();
		builder.set_meta(null);
	}

	abstract class OnSucessActionListener<Response> implements ActionListener<Response> {

		private final RestChannel channel;

		public OnSucessActionListener(RestChannel channel) {
			super();
			this.channel = channel;
		}

		@Override
		public final void onFailure(Exception e) {
			internalErrorResponse(channel, "Error "+e.getMessage());
		}

	}

	protected void saveAnUpdateConfigs(final Client client, final RestRequest request, final CType cType,
									   final SecurityDynamicConfiguration<?> configuration, OnSucessActionListener<IndexResponse> actionListener) {
		final IndexRequest ir = new IndexRequest(this.opendistroIndex);

		//final String type = "_doc";
		final String id = cType.toLCString();

		configuration.removeStatic();

		try {
			client.index(ir.id(id)
							.setRefreshPolicy(RefreshPolicy.IMMEDIATE)
							.setIfSeqNo(configuration.getSeqNo())
							.setIfPrimaryTerm(configuration.getPrimaryTerm())
							.source(id, XContentHelper.toXContent(configuration, XContentType.JSON, false)),
					new ConfigUpdatingActionListener<IndexResponse>(client, actionListener));
		} catch (IOException e) {
			throw ExceptionsHelper.convertToElastic(e);
		}
	}

	private static class ConfigUpdatingActionListener<Response> implements ActionListener<Response>{

		private final Client client;
		private final ActionListener<Response> delegate;

		public ConfigUpdatingActionListener(Client client, ActionListener<Response> delegate) {
			super();
			this.client = client;
			this.delegate = delegate;
		}

		@Override
		public void onResponse(Response response) {

			final ConfigUpdateRequest cur = new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0]));

			client.execute(ConfigUpdateAction.INSTANCE, cur, new ActionListener<ConfigUpdateResponse>() {
				@Override
				public void onResponse(final ConfigUpdateResponse ur) {
					if(ur.hasFailures()) {
						delegate.onFailure(ur.failures().get(0));
						return;
					}
					delegate.onResponse(response);
				}

				@Override
				public void onFailure(final Exception e) {
					delegate.onFailure(e);
				}
			});

		}

		@Override
		public void onFailure(Exception e) {
			delegate.onFailure(e);
		}

	}

	@Override
	protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

		// consume all parameters first so we can return a correct HTTP status,
		// not 400
		consumeParameters(request);

		// check if .opendistro_security index has been initialized
		if (!ensureIndexExists()) {
			return channel -> internalErrorResponse(channel, ErrorType.SECURITY_NOT_INITIALIZED.getMessage());
		}

		// check if request is authorized
		String authError = restApiPrivilegesEvaluator.checkAccessPermissions(request, getEndpoint());

		if (authError != null) {
			log.error("No permission to access REST API: " + authError);
			final User user = (User) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
			auditLog.logMissingPrivileges(authError, user == null ? null : user.getName(), request);
			// for rest request
			request.params().clear();
			return channel -> forbidden(channel, "No permission to access REST API: " + authError);
		}

		final Object originalUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
		final Object originalRemoteAddress = threadPool.getThreadContext()
				.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
		final Object originalOrigin = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

		return channel -> {

			try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {

				threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
				threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUser);
				threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, originalRemoteAddress);
				threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originalOrigin);

				handleApiRequest(channel, request, client);

			}
		};
	}

	protected boolean checkConfigUpdateResponse(final ConfigUpdateResponse response) {

		final int nodeCount = cs.state().getNodes().getNodes().size();
		final int expectedConfigCount = 1;

		boolean success = response.getNodes().size() == nodeCount;
		if (!success) {
			log.error(
					"Expected " + nodeCount + " nodes to return response, but got only " + response.getNodes().size());
		}

		for (final String nodeId : response.getNodesMap().keySet()) {
			final ConfigUpdateNodeResponse node = response.getNodesMap().get(nodeId);
			final boolean successNode = node.getUpdatedConfigTypes() != null
					&& node.getUpdatedConfigTypes().length == expectedConfigCount;

			if (!successNode) {
				log.error("Expected " + expectedConfigCount + " config types for node " + nodeId + " but got only "
						+ Arrays.toString(node.getUpdatedConfigTypes()));
			}

			success = success && successNode;
		}

		return success;
	}

	protected static XContentBuilder convertToJson(RestChannel channel, ToXContent toxContent) {
		try {
			XContentBuilder builder = channel.newBuilder();
			toxContent.toXContent(builder, ToXContent.EMPTY_PARAMS);
			return builder;
		} catch (IOException e) {
			throw ExceptionsHelper.convertToElastic(e);
		}
	}

	protected void response(RestChannel channel, RestStatus status, String message) {

		try {
			final XContentBuilder builder = channel.newBuilder();
			builder.startObject();
			builder.field("status", status.name());
			builder.field("message", message);
			builder.endObject();
			channel.sendResponse(new BytesRestResponse(status, builder));
		} catch (IOException e) {
			throw ExceptionsHelper.convertToElastic(e);
		}
	}

	protected void successResponse(RestChannel channel, SecurityDynamicConfiguration<?> response) {
		channel.sendResponse(
				new BytesRestResponse(RestStatus.OK, convertToJson(channel, response)));
	}

	protected void successResponse(RestChannel channel) {
		try {
			final XContentBuilder builder = channel.newBuilder();
			builder.startObject();
			channel.sendResponse(
					new BytesRestResponse(RestStatus.OK, builder));
		} catch (IOException e) {
			internalErrorResponse(channel, "Unable to fetch license: " + e.getMessage());
			log.error("Cannot fetch convert license to XContent due to", e);
		}
	}

	protected void badRequestResponse(RestChannel channel, AbstractConfigurationValidator validator) {
		channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent(channel)));
	}

	protected void successResponse(RestChannel channel, String message) {
		response(channel, RestStatus.OK, message);
	}

	protected void createdResponse(RestChannel channel, String message) {
		response(channel, RestStatus.CREATED, message);
	}

	protected void badRequestResponse(RestChannel channel, String message) {
		response(channel, RestStatus.BAD_REQUEST, message);
	}

	protected void notFound(RestChannel channel, String message) {
		response(channel, RestStatus.NOT_FOUND, message);
	}

	protected void forbidden(RestChannel channel, String message) {
		response(channel, RestStatus.FORBIDDEN, message);
	}

	protected void internalErrorResponse(RestChannel channel, String message) {
		response(channel, RestStatus.INTERNAL_SERVER_ERROR, message);
	}

	protected void unprocessable(RestChannel channel, String message) {
		response(channel, RestStatus.UNPROCESSABLE_ENTITY, message);
	}

	protected void notImplemented(RestChannel channel, Method method) {
		response(channel, RestStatus.NOT_IMPLEMENTED,
				"Method " + method.name() + " not supported for this action.");
	}

	protected final boolean isReserved(SecurityDynamicConfiguration<?> configuration, String resourceName) {
		if(isStatic(configuration, resourceName)) { //static is also always reserved
			return true;
		}

		final Object o = configuration.getCEntry(resourceName);
		return o != null && o instanceof Hideable && ((Hideable) o).isReserved();
	}

	protected final boolean isHidden(SecurityDynamicConfiguration<?> configuration, String resourceName) {
		final Object o = configuration.getCEntry(resourceName);
		return o != null && o instanceof Hideable && ((Hideable) o).isHidden();
	}

	protected final boolean isStatic(SecurityDynamicConfiguration<?> configuration, String resourceName) {
		final Object o = configuration.getCEntry(resourceName);
		return o != null && o instanceof StaticDefinable && ((StaticDefinable) o).isStatic();
	}

	/**
	 * Consume all defined parameters for the request. Before we handle the
	 * request in subclasses where we actually need the parameter, some global
	 * checks are performed, e.g. check whether the .security_index index exists. Thus, the
	 * parameter(s) have not been consumed, and ES will always return a 400 with
	 * an internal error message.
	 *
	 * @param request
	 */
	protected void consumeParameters(final RestRequest request) {
		request.param("name");
	}

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	protected abstract Endpoint getEndpoint();

	protected boolean isSuperAdmin() {
		User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
		return adminDNs.isAdmin(user);
	}

	protected boolean isReservedAndAccessible(final SecurityDynamicConfiguration<?> existingConfiguration,
											  String name) {
		if( isReserved(existingConfiguration, name) && !isSuperAdmin()) {
			return true;
		}
		return false;
	}

}
