/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.support;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import com.amazon.opendistroforelasticsearch.security.auth.AuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.AuthorizationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.HTTPAuthenticator;
import com.amazon.opendistroforelasticsearch.security.auth.internal.InternalAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.internal.NoOpAuthenticationBackend;
import com.amazon.opendistroforelasticsearch.security.auth.internal.NoOpAuthorizationBackend;
import com.amazon.opendistroforelasticsearch.security.http.HTTPBasicAuthenticator;
import com.amazon.opendistroforelasticsearch.security.http.HTTPClientCertAuthenticator;
import com.amazon.opendistroforelasticsearch.security.http.HTTPProxyAuthenticator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.transport.InterClusterRequestEvaluator;

public enum ModuleType implements Serializable {

	REST_MANAGEMENT_API("REST Management API", "com.amazon.opendistroforelasticsearch.security.dlic.rest.api.OpenDistroSecurityRestApiActions", Boolean.TRUE),
	DLSFLS("Document- and Field-Level Security", "com.amazon.opendistroforelasticsearch.security.configuration.OpenDistroSecurityFlsDlsIndexSearcherWrapper", Boolean.TRUE),
	AUDITLOG("Audit Logging", "com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditLogImpl", Boolean.TRUE),
	MULTITENANCY("Kibana Multitenancy", "com.amazon.opendistroforelasticsearch.security.configuration.PrivilegesInterceptorImpl", Boolean.TRUE),
	LDAP_AUTHENTICATION_BACKEND("LDAP authentication backend", "com.amazon.dlic.auth.ldap.backend.LDAPAuthenticationBackend", Boolean.TRUE),
	LDAP_AUTHORIZATION_BACKEND("LDAP authorization backend", "com.amazon.dlic.auth.ldap.backend.LDAPAuthorizationBackend", Boolean.TRUE),
	KERBEROS_AUTHENTICATION_BACKEND("Kerberos authentication backend", "com.amazon.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator", Boolean.TRUE),
	JWT_AUTHENTICATION_BACKEND("JWT authentication backend", "com.amazon.dlic.auth.http.jwt.HTTPJwtAuthenticator", Boolean.TRUE),
	OPENID_AUTHENTICATION_BACKEND("OpenID authentication backend", "com.amazon.dlic.auth.http.jwt.keybyoidc.HTTPJwtKeyByOpenIdConnectAuthenticator", Boolean.TRUE),
	SAML_AUTHENTICATION_BACKEND("SAML authentication backend", "com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator", Boolean.TRUE),
	INTERNAL_USERS_AUTHENTICATION_BACKEND("Internal users authentication backend", InternalAuthenticationBackend.class.getName(), Boolean.FALSE),
	NOOP_AUTHENTICATION_BACKEND("Noop authentication backend", NoOpAuthenticationBackend.class.getName(), Boolean.FALSE),
	NOOP_AUTHORIZATION_BACKEND("Noop authorization backend", NoOpAuthorizationBackend.class.getName(), Boolean.FALSE),
	HTTP_BASIC_AUTHENTICATOR("HTTP Basic Authenticator", HTTPBasicAuthenticator.class.getName(), Boolean.FALSE),
	HTTP_PROXY_AUTHENTICATOR("HTTP Proxy Authenticator", HTTPProxyAuthenticator.class.getName(), Boolean.FALSE),
	HTTP_CLIENTCERT_AUTHENTICATOR("HTTP Client Certificate Authenticator", HTTPClientCertAuthenticator.class.getName(), Boolean.FALSE),
	CUSTOM_HTTP_AUTHENTICATOR("Custom HTTP authenticator", null, Boolean.TRUE),
	CUSTOM_AUTHENTICATION_BACKEND("Custom authentication backend", null, Boolean.TRUE),
	CUSTOM_AUTHORIZATION_BACKEND("Custom authorization backend", null, Boolean.TRUE),
	CUSTOM_INTERCLUSTER_REQUEST_EVALUATOR("Intercluster Request Evaluator", null, Boolean.FALSE),
	CUSTOM_PRINCIPAL_EXTRACTOR("TLS Principal Extractor", null, Boolean.FALSE),
	// COMPLIANCE("Compliance", "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceIndexingOperationListenerImpl", Boolean.TRUE),
	UNKNOWN("Unknown type", null, Boolean.TRUE);

	private String description;
	private String defaultImplClass;
	private Boolean isAdvancedModule = Boolean.TRUE;
	private static Map<String, ModuleType> modulesMap = new HashMap<>();

	static{
		for(ModuleType module : ModuleType.values()) {
			if (module.defaultImplClass != null) {
				modulesMap.put(module.getDefaultImplClass(), module);
			}
		}
	}

	private ModuleType(String description, String defaultImplClass, Boolean isAdvancedModule) {
		this.description = description;
		this.defaultImplClass = defaultImplClass;
		this.isAdvancedModule = isAdvancedModule;
	}

	public static ModuleType getByDefaultImplClass(Class<?> clazz) {
		ModuleType moduleType = modulesMap.get(clazz.getName());
    	if(moduleType == null) {
    		if(HTTPAuthenticator.class.isAssignableFrom(clazz)) {
    			moduleType = ModuleType.CUSTOM_HTTP_AUTHENTICATOR;
    		}

    		if(AuthenticationBackend.class.isAssignableFrom(clazz)) {
    			moduleType = ModuleType.CUSTOM_AUTHENTICATION_BACKEND;
    		}

    		if(AuthorizationBackend.class.isAssignableFrom(clazz)) {
    			moduleType = ModuleType.CUSTOM_AUTHORIZATION_BACKEND;
    		}

    		if(AuthorizationBackend.class.isAssignableFrom(clazz)) {
    			moduleType = ModuleType.CUSTOM_AUTHORIZATION_BACKEND;
    		}

    		if(InterClusterRequestEvaluator.class.isAssignableFrom(clazz)) {
    			moduleType = ModuleType.CUSTOM_INTERCLUSTER_REQUEST_EVALUATOR;
    		}

    		if(PrincipalExtractor.class.isAssignableFrom(clazz)) {
    			moduleType = ModuleType.CUSTOM_PRINCIPAL_EXTRACTOR;
    		}
    	}
    	if(moduleType == null) {
    		moduleType = ModuleType.UNKNOWN;
    	}
    	return moduleType;
	}

	public String getDescription() {
		return this.description;
	}

	public String getDefaultImplClass() {
		return defaultImplClass;
	}

	public Boolean isAdvancedModule() {
		return isAdvancedModule;
	}


}
