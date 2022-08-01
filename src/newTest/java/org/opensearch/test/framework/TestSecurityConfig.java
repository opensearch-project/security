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

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.common.Strings;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.security.action.configupdate.ConfigUpdateAction;
import org.opensearch.security.action.configupdate.ConfigUpdateRequest;
import org.opensearch.security.action.configupdate.ConfigUpdateResponse;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.NestedValueMap;
import org.opensearch.test.framework.cluster.NestedValueMap.Path;
import org.opensearch.test.framework.cluster.OpenSearchClientProvider.UserCredentialsHolder;

public class TestSecurityConfig {

	private static final Logger log = LogManager.getLogger(TestSecurityConfig.class);

	private NestedValueMap overrideSecurityConfigSettings;
	private NestedValueMap overrideUserSettings;
	private NestedValueMap overrideRoleSettings;
	private NestedValueMap overrideRoleMappingSettings;	
	private String indexName = ".opendistro_security";
	private Map<String, Supplier<Object>> variableSuppliers = new HashMap<>();

	public TestSecurityConfig() {

	}

	public TestSecurityConfig configIndexName(String configIndexName) {
		this.indexName = configIndexName;
		return this;
	}

	public TestSecurityConfig var(String name, Supplier<Object> variableSupplier) {
		this.variableSuppliers.put(name, variableSupplier);
		return this;
	}

	public TestSecurityConfig securityConfigSettings(String keyPath, Object value, Object... more) {
		if (overrideSecurityConfigSettings == null) {
			overrideSecurityConfigSettings = new NestedValueMap();
		}

		overrideSecurityConfigSettings.put(NestedValueMap.Path.parse(keyPath), value);

		for (int i = 0; i < more.length - 1; i += 2) {
			overrideSecurityConfigSettings.put(NestedValueMap.Path.parse(String.valueOf(more[i])), more[i + 1]);
		}

		return this;
	}

	public TestSecurityConfig xff(String proxies) {
		if (overrideSecurityConfigSettings == null) {
			overrideSecurityConfigSettings = new NestedValueMap();
		}

		overrideSecurityConfigSettings.put(new NestedValueMap.Path("config", "dynamic", "http", "xff"),
				NestedValueMap.of("enabled", true, "internalProxies", proxies));

		return this;
	}

    public TestSecurityConfig anonymousAuth(boolean anonymousAuthEnabled) {
        if (overrideSecurityConfigSettings == null) {
        	overrideSecurityConfigSettings = new NestedValueMap();
        }

        overrideSecurityConfigSettings.put(new NestedValueMap.Path("config", "dynamic", "http"),
                NestedValueMap.of("anonymous_auth_enabled", anonymousAuthEnabled));

        return this;
    }
    
    public TestSecurityConfig authc(AuthcDomain authcDomain) {
        if (overrideSecurityConfigSettings == null) {
            overrideSecurityConfigSettings = new NestedValueMap();
        }

        overrideSecurityConfigSettings.put(new NestedValueMap.Path("config", "dynamic", "authc"), authcDomain.toMap());

        return this;
    }

	public TestSecurityConfig user(User user) {
		if (user.roleNames != null) {
			return this.user(user.name, user.password, user.attributes, user.roleNames);
		} else {
			return this.user(user.name, user.password, user.attributes, user.roles);
		}
	}

	public TestSecurityConfig user(String name, String password, String... sgRoles) {
		return user(name, password, null, sgRoles);
	}

	public TestSecurityConfig user(String name, String password, Map<String, Object> attributes, String... securityRoles) {
		if (overrideUserSettings == null) {
			overrideUserSettings = new NestedValueMap();
		}

		overrideUserSettings.put(new NestedValueMap.Path(name, "hash"), hash(password.toCharArray()));

		if (securityRoles != null && securityRoles.length > 0) {
			overrideUserSettings.put(new NestedValueMap.Path(name, "opensearch_security_roles"), securityRoles);
		}

		if (attributes != null && attributes.size() != 0) {
			for (Map.Entry<String, Object> attr : attributes.entrySet()) {
				overrideUserSettings.put(new NestedValueMap.Path(name, "attributes", attr.getKey()), attr.getValue());
			}
		}

		return this;
	}

	public TestSecurityConfig user(String name, String password, Role... sgRoles) {
		return user(name, password, null, sgRoles);
	}

	public TestSecurityConfig user(String name, String password, Map<String, Object> attributes, Role... sgRoles) {
		if (overrideUserSettings == null) {
			overrideUserSettings = new NestedValueMap();
		}

		overrideUserSettings.put(new NestedValueMap.Path(name, "hash"), hash(password.toCharArray()));

		if (sgRoles != null && sgRoles.length > 0) {
			String roleNamePrefix = "user_" + name + "__";

			overrideUserSettings.put(new NestedValueMap.Path(name, "opendistro_security_roles"),
					Arrays.asList(sgRoles).stream().map((r) -> roleNamePrefix + r.name).collect(Collectors.toList()));
			roles(roleNamePrefix, sgRoles);
		}

		if (attributes != null && attributes.size() != 0) {
			for (Map.Entry<String, Object> attr : attributes.entrySet()) {
				overrideUserSettings.put(new NestedValueMap.Path(name, "attributes", attr.getKey()), attr.getValue());
			}
		}

		return this;
	}

	public TestSecurityConfig roles(Role... roles) {
		return roles("", roles);
	}

	public TestSecurityConfig roles(String roleNamePrefix, Role... roles) {
		if (overrideRoleSettings == null) {
			overrideRoleSettings = new NestedValueMap();
		}

		for (Role role : roles) {

			String name = roleNamePrefix + role.name;

			if (role.clusterPermissions.size() > 0) {
				overrideRoleSettings.put(new NestedValueMap.Path(name, "cluster_permissions"), role.clusterPermissions);
			}

			if (role.indexPermissions.size() > 0) {
				overrideRoleSettings.put(new NestedValueMap.Path(name, "index_permissions"),
						role.indexPermissions.stream().map((p) -> p.toJsonMap()).collect(Collectors.toList()));
			}
		}

		return this;
	}

	public TestSecurityConfig roleMapping(RoleMapping... roleMappings) {
		if (overrideRoleMappingSettings == null) {
			overrideRoleMappingSettings = new NestedValueMap();
		}

		for (RoleMapping roleMapping : roleMappings) {

			String name = roleMapping.name;

			if (roleMapping.backendRoles.size() > 0) {
				overrideRoleMappingSettings.put(new NestedValueMap.Path(name, "backend_roles"),
						roleMapping.backendRoles);
			}

			if (roleMapping.users.size() > 0) {
				overrideRoleMappingSettings.put(new NestedValueMap.Path(name, "users"), roleMapping.users);
			}
		}

		return this;
	}

	public TestSecurityConfig roleToRoleMapping(Role role, String... backendRoles) {
		return this.roleMapping(new RoleMapping(role.name).backendRoles(backendRoles));
	}

	public static class User implements UserCredentialsHolder {

		public final static TestSecurityConfig.User USER_ADMIN = new TestSecurityConfig.User("admin")
				.roles(new Role("allaccess").indexPermissions("*").on("*").clusterPermissions("*"));
		
		private String name;
		private String password;
		private Role[] roles;
		private String[] roleNames;
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
			this.roles = roles;
			return this;
		}

		public User roles(String... roles) {
			this.roleNames = roles;
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
			Set<String> result = new HashSet<String>();

			if (roleNames != null) {
				result.addAll(Arrays.asList(roleNames));
			}

			if (roles != null) {
				result.addAll(Arrays.asList(roles).stream().map(Role::getName).collect(Collectors.toSet()));
			}

			return result;
		}

	}

	public static class Role {
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

		public String getName() {
			return name;
		}
	}

	public static class RoleMapping {
		private String name;
		private List<String> backendRoles = new ArrayList<>();
		private List<String> users = new ArrayList<>();

		public RoleMapping(String name) {
			this.name = name;
		}

		public RoleMapping backendRoles(String... backendRoles) {
			this.backendRoles.addAll(Arrays.asList(backendRoles));
			return this;
		}

		public RoleMapping users(String... users) {
			this.users.addAll(Arrays.asList(users));
			return this;
		}

	}

	public static class IndexPermission {
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
		
		public NestedValueMap toJsonMap() {
			NestedValueMap result = new NestedValueMap();

			result.put("index_patterns", indexPatterns);
			result.put("allowed_actions", allowedActions);

			if (dlsQuery != null) {
				result.put("dls", dlsQuery);
			}

			if (fls != null) {
				result.put("fls", fls);
			}

			if (maskedFields != null) {
				result.put("masked_fields", maskedFields);
			}

			return result;
		}

	}

    public static class AuthcDomain {

    	public final static AuthcDomain AUTHC_HTTPBASIC_INTERNAL = new TestSecurityConfig.AuthcDomain("basic", 0)
    			.httpAuthenticator("basic").backend("internal");

        private final String id;
        private boolean enabled = true;
        private boolean transportEnabled = true;
        private int order;
        private List<String> skipUsers = new ArrayList<>();
        private HttpAuthenticator httpAuthenticator;
        private AuthenticationBackend authenticationBackend;
    	
        public AuthcDomain(String id, int order) {
            this.id = id;
            this.order = order;
        }

        public AuthcDomain httpAuthenticator(String type) {
            this.httpAuthenticator = new HttpAuthenticator(type);
            return this;
        }

        public AuthcDomain challengingAuthenticator(String type) {
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

        NestedValueMap toMap() {
            NestedValueMap result = new NestedValueMap();
            result.put(new NestedValueMap.Path(id, "http_enabled"), enabled);
            result.put(new NestedValueMap.Path(id, "transport_enabled"), transportEnabled);
            result.put(new NestedValueMap.Path(id, "order"), order);

            if (httpAuthenticator != null) {
                result.put(new NestedValueMap.Path(id, "http_authenticator"), httpAuthenticator.toMap());
            }

            if (authenticationBackend != null) {
                result.put(new NestedValueMap.Path(id, "authentication_backend"), authenticationBackend.toMap());
            }


            if (skipUsers != null && skipUsers.size() > 0) {
                result.put(new NestedValueMap.Path(id, "skip_users"), skipUsers);
            }

            return result;
        }

        public static class HttpAuthenticator {
            private final String type;
            private boolean challenge;
            private NestedValueMap config = new NestedValueMap();

            public HttpAuthenticator(String type) {
                this.type = type;
            }

            public HttpAuthenticator challenge(boolean challenge) {
                this.challenge = challenge;
                return this;
            }

            public HttpAuthenticator config(Map<String, Object> config) {
                this.config.putAllFromAnyMap(config);
                return this;
            }

            public HttpAuthenticator config(String key, Object value) {
                this.config.put(Path.parse(key), value);
                return this;
            }

            NestedValueMap toMap() {
                NestedValueMap result = new NestedValueMap();
                result.put("type", type);
                result.put("challenge", challenge);
                result.put("config", config);
                return result;
            }
        }

        public static class AuthenticationBackend {
            private final String type;
            private NestedValueMap config = new NestedValueMap();

            public AuthenticationBackend(String type) {
                this.type = type;
            }

            public AuthenticationBackend config(Map<String, Object> config) {
                this.config.putAllFromAnyMap(config);
                return this;
            }

            public AuthenticationBackend config(String key, Object value) {
                this.config.put(Path.parse(key), value);
                return this;
            }

            NestedValueMap toMap() {
                NestedValueMap result = new NestedValueMap();
                result.put("type", type);
                result.put("config", config);
                return result;
            }
        }
    }

    public TestSecurityConfig clone() {
        TestSecurityConfig result = new TestSecurityConfig();
        result.indexName = indexName;
        result.overrideRoleSettings = overrideRoleSettings != null ? overrideRoleSettings.clone() : null;
        result.overrideSecurityConfigSettings = overrideSecurityConfigSettings != null ? overrideSecurityConfigSettings.clone() : null;
        result.overrideUserSettings = overrideUserSettings != null ? overrideUserSettings.clone() : null;

        return result;
    }

	public void initIndex(Client client) {
		Map<String, Object> settings = new HashMap<>();
		if (indexName.startsWith(".")) {
			settings.put("index.hidden", true);
		}
		client.admin().indices().create(new CreateIndexRequest(indexName).settings(settings)).actionGet();

        writeConfigToIndex(client, CType.CONFIG, overrideSecurityConfigSettings);
        writeConfigToIndex(client, CType.ROLES, overrideRoleSettings);
		writeConfigToIndex(client, CType.INTERNALUSERS, overrideUserSettings);
        writeConfigToIndex(client, CType.ROLESMAPPING, overrideRoleMappingSettings);
        writeConfigToIndex(client, CType.ACTIONGROUPS);
        writeConfigToIndex(client, CType.TENANTS);
        
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


    private void writeConfigToIndex(Client client, CType configType) {
        writeConfigToIndex(client, configType, NestedValueMap.createNonCloningMap());
    }

	private void writeConfigToIndex(Client client, CType configType, NestedValueMap overrides) {
		try {

			NestedValueMap  config = NestedValueMap.of(new NestedValueMap.Path("_meta", "type"), configType.toLCString(),
					new NestedValueMap.Path("_meta", "config_version"), 2);

			if (overrides != null) {
				config.overrideLeafs(overrides);
			}

			XContentBuilder builder = XContentFactory.jsonBuilder().map(config);
			String json = Strings.toString(builder);
			
			log.info("Writing " + configType + ":\n" + json);

			client.index(new IndexRequest(indexName).id(configType.toLCString())
					.setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(configType.toLCString(),
							BytesReference.fromByteBuffer(ByteBuffer.wrap(json.getBytes("utf-8")))))
					.actionGet();
		} catch (Exception e) {
			throw new RuntimeException("Error while initializing config for " + indexName, e);
		}
	}
}
