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
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

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
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
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

import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateAction;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateNodeResponse;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator.ErrorType;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;

public abstract class AbstractApiAction extends BaseRestHandler {

	protected final Logger log = LogManager.getLogger(this.getClass());

	protected final IndexBaseConfigurationRepository cl;
	protected final ClusterService cs;
	final ThreadPool threadPool;
	private String opendistrosecurityIndex;
	private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
	protected final AuditLog auditLog;
	protected final Settings settings;

	protected AbstractApiAction(final Settings settings, final Path configPath, final RestController controller,
								final Client client, final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl,
								final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
								ThreadPool threadPool, AuditLog auditLog) {
		super(settings);
		this.settings = settings;
		this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME,
				ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
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

	protected abstract String getConfigName();

	protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {

		// validate additional settings, if any
		AbstractConfigurationValidator validator = getValidator(request, request.content());
		if (!validator.validateSettings()) {
			request.params().clear();
			channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent(channel)));
			return;
		}
		switch (request.method()) {
			case DELETE:
				handleDelete(channel,request, client, validator.settingsBuilder()); break;
			case POST:
				handlePost(channel,request, client, validator.settingsBuilder());break;
			case PUT:
				handlePut(channel,request, client, validator.settingsBuilder());break;
			case GET:
				handleGet(channel,request, client, validator.settingsBuilder());break;
			default:
				throw new IllegalArgumentException(request.method() + " not supported");
		}
	}

	protected void handleDelete(final RestChannel channel, final RestRequest request, final Client client,
								final Settings.Builder additionalSettingsBuilder) throws IOException {
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final Tuple<Long, Settings> existingAsSettings = loadAsSettings(getConfigName(), false);

		if (isHidden(existingAsSettings.v2(), name)) {
			notFound(channel, getResourceName() + " " + name + " not found.");
			return;
		}

		if (isReadOnly(existingAsSettings.v2(), name)) {
			forbidden(channel, "Resource '"+ name +"' is read-only.");
			return;
		}

		final Map<String, Object> config = Utils.convertJsonToxToStructuredMap(Settings.builder().put(existingAsSettings.v2()).build());

		boolean resourceExisted = config.containsKey(name);
		config.remove(name);
		if (resourceExisted) {
			saveAnUpdateConfigs(client, request, getConfigName(), Utils.convertStructuredMapToBytes(config), new OnSucessActionListener<IndexResponse>(channel) {

				@Override
				public void onResponse(IndexResponse response) {
					successResponse(channel, "'" + name + "' deleted.");
				}
			}, existingAsSettings.v1());

		} else {
			notFound(channel, getResourceName() + " " + name + " not found.");
		}
	}

	protected void handlePut(final RestChannel channel, final RestRequest request, final Client client,
							 final Settings.Builder additionalSettingsBuilder) throws IOException {

		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final Tuple<Long, Settings> existingAsSettings = loadAsSettings(getConfigName(), false);

		if (isHidden(existingAsSettings.v2(), name)) {
			forbidden(channel, "Resource '"+ name +"' is not available.");
			return;
		}

		if (isReadOnly(existingAsSettings.v2(), name)) {
			forbidden(channel, "Resource '"+ name +"' is read-only.");
			return;
		}

		if (log.isTraceEnabled()) {
			log.trace(additionalSettingsBuilder.build());
		}

		final Map<String, Object> con = Utils.convertJsonToxToStructuredMap(existingAsSettings.v2());

		boolean existed = con.containsKey(name);

		con.put(name, Utils.convertJsonToxToStructuredMap(additionalSettingsBuilder.build()));

		saveAnUpdateConfigs(client, request, getConfigName(), Utils.convertStructuredMapToBytes(con), new OnSucessActionListener<IndexResponse>(channel) {

			@Override
			public void onResponse(IndexResponse response) {
				if (existed) {
					successResponse(channel, "'" + name + "' updated.");
				} else {
					createdResponse(channel, "'" + name + "' created.");
				}

			}
		}, existingAsSettings.v1());

	}

	protected void handlePost(final RestChannel channel, final RestRequest request, final Client client,
							  final Settings.Builder additionalSettings) throws IOException {
		notImplemented(channel, Method.POST);
	}

	protected void handleGet(final RestChannel channel, RestRequest request, Client client, Builder additionalSettings)
			throws IOException{

		final String resourcename = request.param("name");

		final Tuple<Long, Settings.Builder> settingsBuilder = load(getConfigName(), true);

		// filter hidden resources and sensitive settings
		filter(settingsBuilder.v2());

		final Settings configurationSettings = settingsBuilder.v2().build();

		// no specific resource requested, return complete config
		if (resourcename == null || resourcename.length() == 0) {
			channel.sendResponse(
					new BytesRestResponse(RestStatus.OK, convertToJson(channel, configurationSettings)));
			return;
		}



		final Map<String, Object> con =
				new HashMap<>(Utils.convertJsonToxToStructuredMap(Settings.builder().put(configurationSettings).build()))
						.entrySet()
						.stream()
						.filter(f->f.getKey() != null && f.getKey().equals(resourcename)) //copy keys
						.collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));

		if (!con.containsKey(resourcename)) {
			notFound(channel, "Resource '" + resourcename + "' not found.");
			return;
		}

		channel.sendResponse(
				new BytesRestResponse(RestStatus.OK, XContentHelper.convertToJson(Utils.convertStructuredMapToBytes(con), false, false, XContentType.JSON)));

		return;
	}

	protected final Tuple<Long, Settings.Builder> load(final String config, boolean logComplianceEvent) {
		Tuple<Long, Settings> t = loadAsSettings(config, logComplianceEvent);
		return new Tuple<Long, Settings.Builder>(t.v1(), Settings.builder().put(t.v2()));
	}

	protected final Tuple<Long, Settings> loadAsSettings(final String config, boolean logComplianceEvent) {
		return cl.loadConfigurations(Collections.singleton(config), logComplianceEvent).get(config);
	}

	protected boolean ensureIndexExists() {
		if (!cs.state().metaData().hasConcreteIndex(this.opendistrosecurityIndex)) {
			return false;
		}
		return true;
	}

	protected void filter(Settings.Builder builder) {
		Settings settings = builder.build();

		for (String key: settings.names()) {
			if (settings.getAsBoolean(key+".hidden", false)) {
				for (String subKey : settings.getByPrefix(key).keySet()) {
					builder.remove(key+subKey);
				}
			}
		}
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

	protected void saveAnUpdateConfigs(final RestChannel channel, final Client client, final RestRequest request, final String config,
									   final Settings.Builder settings, OnSucessActionListener<IndexResponse> actionListener, long version) {
		saveAnUpdateConfigs(client, request, config, toSource(channel, settings), actionListener, version);
	}


	protected void saveAnUpdateConfigs(final Client client, final RestRequest request, final String config,
									   final BytesReference bytesRef, OnSucessActionListener<IndexResponse> actionListener, long version) {
		final IndexRequest ir = new IndexRequest(this.opendistrosecurityIndex);

		String type = "security";
		String id = config;

		if (cs.state().metaData().index(this.opendistrosecurityIndex).mapping("config") != null) {
			type = config;
			id = "0";
		}

		client.index(ir.type(type).id(id)
						.setRefreshPolicy(RefreshPolicy.IMMEDIATE)
						.version(version)
						.source(config, bytesRef),
				new ConfigUpdatingActionListener<IndexResponse>(client, actionListener));
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

			final ConfigUpdateRequest cur = new ConfigUpdateRequest(new String[] { "config", "roles", "rolesmapping", "internalusers", "actiongroups" });

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

		// check if Security index has been initialized
		if (!ensureIndexExists()) {
			return channel -> channel.sendResponse(
					new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, ErrorType.OPENDISTRO_SECURITY_NOT_INITIALIZED.getMessage())); // TODO
			// return
			// json
		}

		// check if request is authorized
		String authError = restApiPrivilegesEvaluator.checkAccessPermissions(request, getEndpoint());

		if (authError != null) {
			logger.error("No permission to access REST API: " + authError);
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

	protected static BytesReference toSource(RestChannel channel, final Settings.Builder settingsBuilder) { //not throws
		try {
			final XContentBuilder builder = channel.newBuilder();
			builder.startObject(); // 1
			settingsBuilder.build().toXContent(builder, ToXContent.EMPTY_PARAMS);
			builder.endObject(); // 2
			return BytesReference.bytes(builder);
		} catch (IOException e) {
			throw ExceptionsHelper.convertToElastic(e);
		}

	}

	protected boolean checkConfigUpdateResponse(final ConfigUpdateResponse response) {

		final int nodeCount = cs.state().getNodes().getNodes().size();
		final int expectedConfigCount = 1;

		boolean success = response.getNodes().size() == nodeCount;
		if (!success) {
			logger.error(
					"Expected " + nodeCount + " nodes to return response, but got only " + response.getNodes().size());
		}

		for (final String nodeId : response.getNodesMap().keySet()) {
			final ConfigUpdateNodeResponse node = response.getNodesMap().get(nodeId);
			final boolean successNode = node.getUpdatedConfigTypes() != null
					&& node.getUpdatedConfigTypes().length == expectedConfigCount;

			if (!successNode) {
				logger.error("Expected " + expectedConfigCount + " config types for node " + nodeId + " but got only "
						+ Arrays.toString(node.getUpdatedConfigTypes()));
			}

			success = success && successNode;
		}

		return success;
	}

	protected static XContentBuilder convertToJson(RestChannel channel, Settings settings) {
		try {
			XContentBuilder builder = channel.newBuilder();
			builder.startObject();
			settings.toXContent(builder, ToXContent.EMPTY_PARAMS);
			builder.endObject();
			return builder;
		} catch (IOException e) {
			throw ExceptionsHelper.convertToElastic(e);
		}
	}

	protected void response(RestChannel channel, RestStatus status, String statusString, String message) {

		try {
			final XContentBuilder builder = channel.newBuilder();
			builder.startObject();
			builder.field("status", statusString);
			builder.field("message", message);
			builder.endObject();
			channel.sendResponse(new BytesRestResponse(status, builder));
		} catch (IOException e) {
			throw ExceptionsHelper.convertToElastic(e);
		}
	}

	protected void successResponse(RestChannel channel, String message) {
		response(channel, RestStatus.OK, RestStatus.OK.name(), message);
	}

	protected void createdResponse(RestChannel channel, String message) {
		response(channel, RestStatus.CREATED, RestStatus.CREATED.name(), message);
	}

	protected void badRequestResponse(RestChannel channel, String message) {
		response(channel, RestStatus.BAD_REQUEST, RestStatus.BAD_REQUEST.name(), message);
	}

	protected void notFound(RestChannel channel, String message) {
		response(channel, RestStatus.NOT_FOUND, RestStatus.NOT_FOUND.name(), message);
	}

	protected void forbidden(RestChannel channel, String message) {
		response(channel, RestStatus.FORBIDDEN, RestStatus.FORBIDDEN.name(), message);
	}

	protected void internalErrorResponse(RestChannel channel, String message) {
		response(channel, RestStatus.INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.name(), message);
	}

	protected void unprocessable(RestChannel channel, String message) {
		response(channel, RestStatus.UNPROCESSABLE_ENTITY, RestStatus.UNPROCESSABLE_ENTITY.name(), message);
	}

	protected void notImplemented(RestChannel channel, Method method) {
		response(channel, RestStatus.NOT_IMPLEMENTED, RestStatus.NOT_IMPLEMENTED.name(),
				"Method " + method.name() + " not supported for this action.");
	}

	protected boolean isReadOnly(Settings settings, String resourceName) {
		return settings.getAsBoolean(resourceName+ "." + ConfigConstants.CONFIGKEY_READONLY, Boolean.FALSE);
	}

	protected boolean isHidden(Settings settings, String resourceName) {
		return settings.getAsBoolean(resourceName+ "." + ConfigConstants.CONFIGKEY_HIDDEN, Boolean.FALSE);
	}

	/**
	 * Consume all defined parameters for the request. Before we handle the
	 * request in subclasses where we actually need the parameter, some global
	 * checks are performed, e.g. check whether the Security index exists. Thus, the
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

}