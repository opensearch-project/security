/*
* Copyright 2021 floragunn GmbH
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

/*
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
* Modifications Copyright OpenSearch Contributors. See
* GitHub history for details.
*/

package org.opensearch.test.framework;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.Strings;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.framework.cluster.OpenSearchClientProvider.UserCredentialsHolder;

/**
* This class allows the declarative specification of the security configuration; in particular:
*
* - config.yml
* - internal_users.yml
* - roles.yml
* - roles_mapping.yml
*
* The class does the whole round-trip, i.e., the configuration is serialized to YAML/JSON and then written to
* the configuration index of the security plugin.
*/
public class TestSecurityConfig {

	private static final Logger log = LogManager.getLogger(TestSecurityConfig.class);

	private Config config = new Config();
	private Map<String, User> internalUsers = new LinkedHashMap<>();
	private Map<String, Role> roles = new LinkedHashMap<>();

	private AuditConfiguration auditConfiguration;

	private String indexName = ".opendistro_security";

	public TestSecurityConfig() {

	}

	public TestSecurityConfig configIndexName(String configIndexName) {
		this.indexName = configIndexName;
		return this;
	}

	public TestSecurityConfig anonymousAuth(boolean anonymousAuthEnabled) {
		config.anonymousAuth(anonymousAuthEnabled);
		return this;
	}
	
	public TestSecurityConfig authc(AuthcDomain authcDomain) {
		config.authc(authcDomain);
		return this;
	}
	public TestSecurityConfig user(User user) {
		this.internalUsers.put(user.name, user);

		for (Role role : user.roles) {
			this.roles.put(role.name, role);
		}

		return this;
	}

	public TestSecurityConfig roles(Role... roles) {
		for (Role role : roles) {
			this.roles.put(role.name, role);
		}

		return this;
	}

	public TestSecurityConfig audit(AuditConfiguration auditConfiguration) {
		this.auditConfiguration = auditConfiguration;
		return this;
	}

	public static class Config implements ToXContentObject {
		private boolean anonymousAuth;
		private Map<String, AuthcDomain> authcDomainMap = new LinkedHashMap<>();

		public Config anonymousAuth(boolean anonymousAuth) {
			this.anonymousAuth = anonymousAuth;
			return this;
		}

		public Config authc(AuthcDomain authcDomain) {
			authcDomainMap.put(authcDomain.id, authcDomain);
			return this;
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			xContentBuilder.startObject();
			xContentBuilder.startObject("dynamic");

			if (anonymousAuth) {
				xContentBuilder.startObject("http");
				xContentBuilder.field("anonymous_auth_enabled", true);
				xContentBuilder.endObject();
			}

			xContentBuilder.field("authc", authcDomainMap);

			xContentBuilder.endObject();
			xContentBuilder.endObject();
			return xContentBuilder;
		}
	}

	public static class User implements UserCredentialsHolder, ToXContentObject {

		public final static TestSecurityConfig.User USER_ADMIN = new TestSecurityConfig.User("admin")
				.roles(new Role("allaccess").indexPermissions("*").on("*").clusterPermissions("*"));
		
		private String name;
		private String password;
		private List<Role> roles = new ArrayList<>();
		private Map<String, Object> attributes = new HashMap<>();

		public User(String name) {
			this.name = name;
			this.password = "secret";
		}

		public User password(String password) {
			this.password = password;
			return this;
		}

		public User roles(Role... roles) {
			// We scope the role names by user to keep tests free of potential side effects
			String roleNamePrefix = "user_" + this.name + "__";
			this.roles.addAll(Arrays.asList(roles).stream().map((r) -> r.clone().name(roleNamePrefix + r.name)).collect(Collectors.toSet()));
			return this;
		}

		public User attr(String key, Object value) {
			this.attributes.put(key, value);
			return this;
		}

		public String getName() {
			return name;
		}

		public String getPassword() {
			return password;
		}

		public Set<String> getRoleNames() {
			return roles.stream().map(Role::getName).collect(Collectors.toSet());
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			xContentBuilder.startObject();

			xContentBuilder.field("hash", hash(password.toCharArray()));

			Set<String> roleNames = getRoleNames();

			if (!roleNames.isEmpty()) {
				xContentBuilder.field("opendistro_security_roles", roleNames);
			}

			if (attributes != null && attributes.size() != 0) {
				xContentBuilder.field("attributes", attributes);
			}

			xContentBuilder.endObject();
			return xContentBuilder;
		}
	}

	public static class AuditFilters implements ToXContentObject {

		private Boolean enabledRest;

		private Boolean enabledTransport;

		private Boolean logRequestBody;

		private Boolean resolveIndices;

		private Boolean resolveBulkRequests;

		private Boolean excludeSensitiveHeaders;

		private List<String> ignoreUsers;

		private List<String> ignoreRequests;

		private List<String> disabledRestCategories;

		private List<String> disabledTransportCategories;

		public AuditFilters(){
			this.enabledRest = false;
			this.enabledTransport = false;

			this.logRequestBody = true;
			this.resolveIndices = true;
			this.resolveBulkRequests = false;
			this.excludeSensitiveHeaders = true;

			this.ignoreUsers = Collections.emptyList();
			this.ignoreRequests = Collections.emptyList();
			this.disabledRestCategories = Collections.emptyList();
			this.disabledTransportCategories = Collections.emptyList();
		}

		public AuditFilters enabledRest(boolean enabled) {
			this.enabledRest = enabled;
			return this;
		}

		public AuditFilters enabledTransport(boolean enabled) {
			this.enabledTransport = enabled;
			return this;
		}

		public AuditFilters logRequestBody(boolean logRequestBody){
			this.logRequestBody = logRequestBody;
			return this;
		}

		public AuditFilters resolveIndices(boolean resolveIndices) {
			this.resolveIndices = resolveIndices;
			return this;
		}

		public AuditFilters resolveBulkRequests(boolean resolveBulkRequests) {
			this.resolveBulkRequests = resolveBulkRequests;
			return this;
		}

		public AuditFilters excludeSensitiveHeaders(boolean excludeSensitiveHeaders) {
			this.excludeSensitiveHeaders = excludeSensitiveHeaders;
			return this;
		}

		public AuditFilters ignoreUsers(List<String> ignoreUsers) {
			this.ignoreUsers = ignoreUsers;
			return this;
		}

		public AuditFilters ignoreRequests(List<String> ignoreRequests) {
			this.ignoreRequests =ignoreRequests;
			return this;
		}

		public AuditFilters disabledRestCategories(List<String> disabledRestCategories) {
			this.disabledRestCategories = disabledRestCategories;
			return this;
		}

		public AuditFilters disabledTransportCategories(List<String> disabledTransportCategories) {
			this.disabledTransportCategories = disabledTransportCategories;
			return this;
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			xContentBuilder.startObject();
			xContentBuilder.field("enable_rest", enabledRest);
			xContentBuilder.field("enable_transport", enabledTransport);
			xContentBuilder.field("resolve_indices", resolveIndices);
			xContentBuilder.field("log_request_body", logRequestBody);
			xContentBuilder.field("resolve_bulk_requests", resolveBulkRequests);
			xContentBuilder.field("exclude_sensitive_headers", excludeSensitiveHeaders);
			xContentBuilder.field("ignore_users", ignoreUsers);
			xContentBuilder.field("ignore_requests", ignoreRequests);
			xContentBuilder.field("disabled_rest_categories", disabledRestCategories);
			xContentBuilder.field("disabled_transport_categories", disabledTransportCategories);
			xContentBuilder.endObject();
			return xContentBuilder;
		}
	}

	public static class AuditCompliance implements ToXContentObject {

		private boolean enabled = false;

		private Boolean writeLogDiffs;

		private List<String> readIgnoreUsers;

		private List<String> writeWatchedIndices;

		private List<String> writeIgnoreUsers;

		private Boolean readMetadataOnly;

		private Boolean writeMetadataOnly;

		private Boolean externalConfig;

		private Boolean internalConfig;

		public AuditCompliance enabled(boolean enabled) {
			this.enabled = enabled;
			this.writeLogDiffs = false;
			this.readIgnoreUsers = Collections.emptyList();
			this.writeWatchedIndices = Collections.emptyList();
			this.writeIgnoreUsers = Collections.emptyList();
			this.readMetadataOnly = false;
			this.writeMetadataOnly = false;
			this.externalConfig = false;
			this.internalConfig = false;
			return this;
		}

		public AuditCompliance writeLogDiffs(boolean writeLogDiffs) {
			this.writeLogDiffs = writeLogDiffs;
			return this;
		}

		public AuditCompliance readIgnoreUsers(List<String> list) {
			this.readIgnoreUsers = list;
			return this;
		}

		public AuditCompliance writeWatchedIndices(List<String> list) {
			this.writeWatchedIndices = list;
			return this;
		}

		public AuditCompliance writeIgnoreUsers(List<String> list) {
			this.writeIgnoreUsers = list;
			return this;
		}

		public AuditCompliance readMetadataOnly(boolean readMetadataOnly) {
			this.readMetadataOnly = readMetadataOnly;
			return this;
		}

		public AuditCompliance writeMetadataOnly(boolean writeMetadataOnly) {
			this.writeMetadataOnly = writeMetadataOnly;
			return this;
		}

		public AuditCompliance externalConfig(boolean externalConfig) {
			this.externalConfig = externalConfig;
			return this;
		}

		public AuditCompliance internalConfig(boolean internalConfig) {
			this.internalConfig = internalConfig;
			return this;
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			xContentBuilder.startObject();
			xContentBuilder.field("enabled", enabled);
			xContentBuilder.field("write_log_diffs", writeLogDiffs);
			xContentBuilder.field("read_ignore_users", readIgnoreUsers);
			xContentBuilder.field("write_watched_indices", writeWatchedIndices);
			xContentBuilder.field("write_ignore_users", writeIgnoreUsers);
			xContentBuilder.field("read_metadata_only", readMetadataOnly);
			xContentBuilder.field("write_metadata_only", writeMetadataOnly);
			xContentBuilder.field("external_config", externalConfig);
			xContentBuilder.field("internal_config", internalConfig);
			xContentBuilder.endObject();
			return xContentBuilder;
		}
	}

	public static class AuditConfiguration implements ToXContentObject {
		private final boolean enabled;

		private AuditFilters filters;

		private AuditCompliance compliance;

		public AuditConfiguration(boolean enabled) {
			this.filters = new AuditFilters();
			this.compliance = new AuditCompliance();
			this.enabled = enabled;
		}

		public boolean isEnabled() {
			return enabled;
		}

		public AuditConfiguration filters(AuditFilters filters) {
			this.filters = filters;
			return this;
		}

		public AuditConfiguration compliance(AuditCompliance auditCompliance) {
			this.compliance = auditCompliance;
			return this;
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			// json built here must be deserialized to org.opensearch.security.auditlog.config.AuditConfig
			xContentBuilder.startObject();
			xContentBuilder.field("enabled", enabled);

			xContentBuilder.field("audit", filters);
			xContentBuilder.field("compliance", compliance);

			xContentBuilder.endObject();
			return xContentBuilder;
		}
	}

	public static class Role implements ToXContentObject {
		public static Role ALL_ACCESS = new Role("all_access").clusterPermissions("*").indexPermissions("*").on("*");

		private String name;
		private List<String> clusterPermissions = new ArrayList<>();

		private List<IndexPermission> indexPermissions = new ArrayList<>();

		public Role(String name) {
			this.name = name;
		}

		public Role clusterPermissions(String... clusterPermissions) {
			this.clusterPermissions.addAll(Arrays.asList(clusterPermissions));
			return this;
		}

		public IndexPermission indexPermissions(String... indexPermissions) {
			return new IndexPermission(this, indexPermissions);
		}

		public Role name(String name) {
			this.name = name;
			return this;
		}

		public String getName() {
			return name;
		}

		public Role clone() {
			Role role = new Role(this.name);
			role.clusterPermissions.addAll(this.clusterPermissions);
			role.indexPermissions.addAll(this.indexPermissions);
			return role;
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			xContentBuilder.startObject();

			if (!clusterPermissions.isEmpty()) {
				xContentBuilder.field("cluster_permissions", clusterPermissions);
			}

			if (!indexPermissions.isEmpty()) {
				xContentBuilder.field("index_permissions", indexPermissions);
			}

			xContentBuilder.endObject();
			return xContentBuilder;
		}
	}

	public static class IndexPermission implements ToXContentObject {
		private List<String> allowedActions;
		private List<String> indexPatterns;
		private Role role;
		private String dlsQuery;
		private List<String> fls;
		private List<String> maskedFields;

		IndexPermission(Role role, String... allowedActions) {
			this.allowedActions = Arrays.asList(allowedActions);
			this.role = role;
		}

		public IndexPermission dls(String dlsQuery) {
			this.dlsQuery = dlsQuery;
			return this;
		}

		public IndexPermission fls(String... fls) {
			this.fls = Arrays.asList(fls);
			return this;
		}

		public IndexPermission maskedFields(String... maskedFields) {
			this.maskedFields = Arrays.asList(maskedFields);
			return this;
		}

		public Role on(String... indexPatterns) {
			this.indexPatterns = Arrays.asList(indexPatterns);
			this.role.indexPermissions.add(this);
			return this.role;
		}

		public Role on(TestIndex... testindices) {			
			this.indexPatterns = Arrays.asList(testindices).stream().map(TestIndex::getName).collect(Collectors.toList());
			this.role.indexPermissions.add(this);
			return this.role;
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			xContentBuilder.startObject();

			xContentBuilder.field("index_patterns", indexPatterns);
			xContentBuilder.field("allowed_actions", allowedActions);

			if (dlsQuery != null) {
				xContentBuilder.field("dls", dlsQuery);
			}

			if (fls != null) {
				xContentBuilder.field("fls", fls);
			}

			if (maskedFields != null) {
				xContentBuilder.field("masked_fields", maskedFields);
			}

			xContentBuilder.endObject();
			return xContentBuilder;
		}
	}

	public static class AuthcDomain implements ToXContentObject {

		private static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqZbjLUAWc+DZTkinQAdvy1GFjPHPnxheU89hSiWoDD3NOW76H3u3T7cCDdOah2msdxSlBmCBH6wik8qLYkcV8owWukQg3PQmbEhrdPaKo0QCgomWs4nLgtmEYqcZ+QQldd82MdTlQ1QmoQmI9Uxqs1SuaKZASp3Gy19y8su5CV+FZ6BruUw9HELK055sAwl3X7j5ouabXGbcib2goBF3P52LkvbJLuWr5HDZEOeSkwIeqSeMojASM96K5SdotD+HwEyjaTjzRPL2Aa1BEQFWOQ6CFJLyLH7ZStDuPM1mJU1VxIVfMbZrhsUBjAnIhRynmWxML7YlNqkP9j6jyOIYQIDAQAB";

		public final static AuthcDomain AUTHC_HTTPBASIC_INTERNAL = new TestSecurityConfig.AuthcDomain("basic", 0)
				.httpAuthenticatorWithChallenge("basic").backend("internal");

		public final static AuthcDomain AUTHC_HTTPBASIC_INTERNAL_WITHOUT_CHALLENGE = new TestSecurityConfig.AuthcDomain("basic", 0)
			.httpAuthenticator("basic").backend("internal");

		public final static AuthcDomain DISABLED_AUTHC_HTTPBASIC_INTERNAL = new TestSecurityConfig
			.AuthcDomain("basic", 0, false).httpAuthenticator("basic").backend("internal");

		public final static AuthcDomain JWT_AUTH_DOMAIN = new TestSecurityConfig
			.AuthcDomain("jwt", 1)
			.jwtHttpAuthenticator("Authorization", PUBLIC_KEY).backend("noop");

		private final String id;
		private boolean enabled = true;
		private int order;
		private List<String> skipUsers = new ArrayList<>();
		private HttpAuthenticator httpAuthenticator;
		private AuthenticationBackend authenticationBackend;
		
		public AuthcDomain(String id, int order, boolean enabled) {
			this.id = id;
			this.order = order;
			this.enabled = enabled;
		}

		public AuthcDomain(String id, int order) {
			this(id, order, true);
		}

		public AuthcDomain httpAuthenticator(String type) {
			this.httpAuthenticator = new HttpAuthenticator(type);
			return this;
		}

		public AuthcDomain jwtHttpAuthenticator(String headerName, String signingKey) {
			this.httpAuthenticator = new HttpAuthenticator("jwt")
				.challenge(false).config(ImmutableMap.of("jwt_header", headerName, "signing_key", signingKey));
			return this;
		}

		public AuthcDomain httpAuthenticatorWithChallenge(String type) {
			this.httpAuthenticator = new HttpAuthenticator(type).challenge(true);
			return this;
		}

		public AuthcDomain httpAuthenticator(HttpAuthenticator httpAuthenticator) {
			this.httpAuthenticator = httpAuthenticator;
			return this;
		}

		public AuthcDomain backend(String type) {
			this.authenticationBackend = new AuthenticationBackend(type);
			return this;
		}

		public AuthcDomain backend(AuthenticationBackend authenticationBackend) {
			this.authenticationBackend = authenticationBackend;
			return this;
		}

		public AuthcDomain skipUsers(String... users) {
			this.skipUsers.addAll(Arrays.asList(users));
			return this;
		}

		@Override
		public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
			xContentBuilder.startObject();

			xContentBuilder.field("http_enabled", enabled);
			xContentBuilder.field("order", order);

			if (httpAuthenticator != null) {
				xContentBuilder.field("http_authenticator", httpAuthenticator);
			}

			if (authenticationBackend != null) {
				xContentBuilder.field("authentication_backend", authenticationBackend);
			}

			if (skipUsers != null && skipUsers.size() > 0) {
				xContentBuilder.field("skip_users", skipUsers);
			}

			xContentBuilder.endObject();
			return xContentBuilder;
		}

		public static class HttpAuthenticator implements ToXContentObject {
			private final String type;
			private boolean challenge;
			private Map<String, Object> config = new HashMap();

			public HttpAuthenticator(String type) {
				this.type = type;
			}

			public HttpAuthenticator challenge(boolean challenge) {
				this.challenge = challenge;
				return this;
			}

			public HttpAuthenticator config(Map<String, Object> config) {
				this.config.putAll(config);
				return this;
			}

			@Override
			public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
				xContentBuilder.startObject();

				xContentBuilder.field("type", type);
				xContentBuilder.field("challenge", challenge);
				xContentBuilder.field("config", config);

				xContentBuilder.endObject();
				return xContentBuilder;
			}
		}

		public static class AuthenticationBackend implements ToXContentObject {
			private final String type;
			private Map<String, Object> config = new HashMap();

			public AuthenticationBackend(String type) {
				this.type = type;
			}

			public AuthenticationBackend config(Map<String, Object> config) {
				this.config.putAll(config);
				return this;
			}

			@Override
			public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
				xContentBuilder.startObject();

				xContentBuilder.field("type", type);
				xContentBuilder.field("config", config);

				xContentBuilder.endObject();
				return xContentBuilder;
			}
		}
	}

	public void initIndex(Client client) {
		Map<String, Object> settings = new HashMap<>();
		if (indexName.startsWith(".")) {
			settings.put("index.hidden", true);
		}
		client.admin().indices().create(new CreateIndexRequest(indexName).settings(settings)).actionGet();

		writeSingleEntryConfigToIndex(client, CType.CONFIG, config);
		if(auditConfiguration != null) {
			writeSingleEntryConfigToIndex(client, CType.AUDIT, "config", auditConfiguration);
		}
		writeConfigToIndex(client, CType.ROLES, roles);
		writeConfigToIndex(client, CType.INTERNALUSERS, internalUsers);
		writeEmptyConfigToIndex(client, CType.ROLESMAPPING);
		writeEmptyConfigToIndex(client, CType.ACTIONGROUPS);
		writeEmptyConfigToIndex(client, CType.TENANTS);

		ConfigUpdateResponse configUpdateResponse = client.execute(ConfigUpdateAction.INSTANCE,
				new ConfigUpdateRequest(CType.lcStringValues().toArray(new String[0]))).actionGet();

		if (configUpdateResponse.hasFailures()) {
			throw new RuntimeException("ConfigUpdateResponse produced failures: " + configUpdateResponse.failures());
		}
	}


	private static String hash(final char[] clearTextPassword) {
		final byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);
		final String hash = OpenBSDBCrypt.generate((Objects.requireNonNull(clearTextPassword)), salt, 12);
		Arrays.fill(salt, (byte) 0);
		Arrays.fill(clearTextPassword, '\0');
		return hash;
	}

	private void writeEmptyConfigToIndex(Client client, CType configType) {
		writeConfigToIndex(client, configType, Collections.emptyMap());
	}

	private void writeConfigToIndex(Client client, CType configType, Map<String, ? extends ToXContentObject> config) {
		try {
			XContentBuilder builder = XContentFactory.jsonBuilder();

			builder.startObject();
			builder.startObject("_meta");
			builder.field("type", configType.toLCString());
			builder.field("config_version", 2);
			builder.endObject();

			for (Map.Entry<String, ? extends ToXContentObject> entry : config.entrySet()) {
				builder.field(entry.getKey(), entry.getValue());
			}

			builder.endObject();

			String json = Strings.toString(builder);

			log.info("Writing security configuration into index " + configType + ":\n" + json);

			client.index(new IndexRequest(indexName).id(configType.toLCString())
					.setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(configType.toLCString(),
							BytesReference.fromByteBuffer(ByteBuffer.wrap(json.getBytes("utf-8")))))
					.actionGet();
		} catch (Exception e) {
			throw new RuntimeException("Error while initializing config for " + indexName, e);
		}
	}

	private void writeSingleEntryConfigToIndex(Client client, CType configType, ToXContentObject config) {
		writeSingleEntryConfigToIndex(client, configType, configType.toLCString(), config);
	}

	private void writeSingleEntryConfigToIndex(Client client, CType configType, String configurationRoot, ToXContentObject config) {
		try {
			XContentBuilder builder = XContentFactory.jsonBuilder();

			builder.startObject();
			builder.startObject("_meta");
			builder.field("type", configType.toLCString());
			builder.field("config_version", 2);
			builder.endObject();

			builder.field(configurationRoot, config);

			builder.endObject();

			String json = Strings.toString(builder);

			log.info("Writing security plugin configuration into index " + configType + ":\n" + json);

			client.index(new IndexRequest(indexName).id(configType.toLCString())
							.setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(configType.toLCString(),
									BytesReference.fromByteBuffer(ByteBuffer.wrap(json.getBytes("utf-8")))))
					.actionGet();
		} catch (Exception e) {
			throw new RuntimeException("Error while initializing config for " + indexName, e);
		}
	}
}
