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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditTestUtils;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;
import org.junit.Assert;

import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;

public abstract class AbstractRestApiUnitTest extends SingleClusterTest {

	protected RestHelper rh = null;
	protected boolean init = true;

    @Override
    protected String getResourceFolder() {
        return "restapi";
    }

    @Override
	protected final void setup() throws Exception {
		Settings.Builder builder = Settings.builder();

		builder.put("opendistro_security.ssl.http.enabled", true)
				.put("opendistro_security.ssl.http.keystore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
				.put("opendistro_security.ssl.http.truststore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"));

		setup(Settings.EMPTY, new DynamicSecurityConfig(), builder.build(), init);
		rh = restHelper();
		rh.keystore = "restapi/kirk-keystore.jks";
	}

    @Override
	protected final void setup(Settings nodeOverride) throws Exception {
		Settings.Builder builder = Settings.builder();

		builder.put("opendistro_security.ssl.http.enabled", true)
				.put("opendistro_security.ssl.http.keystore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
				.put("opendistro_security.ssl.http.truststore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"))
				.put(nodeOverride);

		System.out.println(builder.toString());

		setup(Settings.EMPTY, new DynamicSecurityConfig(), builder.build(), init);
		rh = restHelper();
		rh.keystore = "restapi/kirk-keystore.jks";
	}

	protected final void setupWithRestRoles() throws Exception {
        setupWithRestRoles(null);
    }

	protected final void setupWithRestRoles(Settings nodeOverride) throws Exception {
		Settings.Builder builder = Settings.builder();

		builder.put("opendistro_security.ssl.http.enabled", true)
				.put("opendistro_security.ssl.http.keystore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
				.put("opendistro_security.ssl.http.truststore_filepath",
						FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"));

		builder.put("opendistro_security.restapi.roles_enabled.0", "opendistro_security_role_klingons");
		builder.put("opendistro_security.restapi.roles_enabled.1", "opendistro_security_role_vulcans");
		builder.put("opendistro_security.restapi.roles_enabled.2", "opendistro_security_test");

		builder.put("opendistro_security.restapi.endpoints_disabled.global.CACHE.0", "*");

		builder.put("opendistro_security.restapi.endpoints_disabled.opendistro_security_role_klingons.conFiGuration.0", "*");
		builder.put("opendistro_security.restapi.endpoints_disabled.opendistro_security_role_klingons.wRongType.0", "WRONGType");
		builder.put("opendistro_security.restapi.endpoints_disabled.opendistro_security_role_klingons.ROLESMAPPING.0", "PUT");
		builder.put("opendistro_security.restapi.endpoints_disabled.opendistro_security_role_klingons.ROLESMAPPING.1", "DELETE");

		builder.put("opendistro_security.restapi.endpoints_disabled.opendistro_security_role_vulcans.CONFIG.0", "*");

		if (null != nodeOverride) {
			builder.put(nodeOverride);
		}

		setup(Settings.EMPTY, new DynamicSecurityConfig(), builder.build(), init);
		rh = restHelper();
		rh.keystore = "restapi/kirk-keystore.jks";

		AuditTestUtils.updateAuditConfig(rh, nodeOverride != null ? nodeOverride : Settings.EMPTY);
	}

	protected void deleteUser(String username) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = true;
		HttpResponse response = rh.executeDeleteRequest("/_opendistro/_security/api/internalusers/" + username, new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected void addUserWithPassword(String username, String password, int status) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = true;
		HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/internalusers/" + username,
				"{\"password\": \"" + password + "\"}", new Header[0]);
		Assert.assertEquals(status, response.getStatusCode());
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected void addUserWithPassword(String username, String password, String[] roles, int status) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = true;
		String payload = "{" + "\"password\": \"" + password + "\"," + "\"backend_roles\": [";
		for (int i = 0; i < roles.length; i++) {
			payload += "\"" + roles[i] + "\"";
			if (i + 1 < roles.length) {
				payload += ",";
			}
		}
		payload += "]}";
		HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/internalusers/" + username, payload, new Header[0]);
		Assert.assertEquals(status, response.getStatusCode());
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected void addUserWithoutPasswordOrHash(String username, String[] roles, int status) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = true;
		String payload = "{ \"backend_roles\": [";
		for (int i = 0; i < roles.length; i++) {
			payload += "\" " + roles[i] + " \"";
			if (i + 1 < roles.length) {
				payload += ",";
			}
		}
		payload += "]}";
		HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/internalusers/" + username, payload, new Header[0]);
		Assert.assertEquals(status, response.getStatusCode());
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected void addUserWithHash(String username, String hash) throws Exception {
		addUserWithHash(username, hash, HttpStatus.SC_OK);
	}

	protected void addUserWithHash(String username, String hash, int status) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = true;
		HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/internalusers/" + username, "{\"hash\": \"" + hash + "\"}",
				new Header[0]);
		Assert.assertEquals(status, response.getStatusCode());
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected void addUserWithPasswordAndHash(String username, String password, String hash, int status) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = true;
		HttpResponse response = rh.executePutRequest("/_opendistro/_security/api/internalusers/" + username, "{\"hash\": \"" + hash + "\", \"password\": \"" + password + "\"}",
				new Header[0]);
		Assert.assertEquals(status, response.getStatusCode());
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected void checkGeneralAccess(int status, String username, String password) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = false;
		Assert.assertEquals(status,
				rh.executeGetRequest("",
						encodeBasicHeader(username, password))
						.getStatusCode());
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected String checkReadAccess(int status, String username, String password, String indexName, String type,
			int id) throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = false;
		String action = indexName + "/" + type + "/" + id;
		HttpResponse response = rh.executeGetRequest(action,
				encodeBasicHeader(username, password));
		int returnedStatus = response.getStatusCode();
		Assert.assertEquals(status, returnedStatus);
		rh.sendAdminCertificate = sendAdminCertificate;
		return response.getBody();

	}

	protected String checkWriteAccess(int status, String username, String password, String indexName, String type,
			int id) throws Exception {

		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = false;
		String action = indexName + "/" + type + "/" + id;
		String payload = "{\"value\" : \"true\"}";
		HttpResponse response = rh.executePutRequest(action, payload,
				encodeBasicHeader(username, password));
		int returnedStatus = response.getStatusCode();
		Assert.assertEquals(status, returnedStatus);
		rh.sendAdminCertificate = sendAdminCertificate;
		return response.getBody();
	}

	protected void setupStarfleetIndex() throws Exception {
		boolean sendAdminCertificate = rh.sendAdminCertificate;
		rh.sendAdminCertificate = true;
		rh.executePutRequest("sf", null, new Header[0]);
		rh.executePutRequest("sf/ships/0", "{\"number\" : \"NCC-1701-D\"}", new Header[0]);
		rh.executePutRequest("sf/public/0", "{\"some\" : \"value\"}", new Header[0]);
		rh.sendAdminCertificate = sendAdminCertificate;
	}

	protected void assertHealthy() throws Exception {
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_opendistro/_security/health?pretty").getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("admin", "admin")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("admin", "admin")).getStatusCode());
	}

	protected Settings defaultNodeSettings(boolean enableRestSSL) {
		Settings.Builder builder = Settings.builder();

		if (enableRestSSL) {
			builder.put("opendistro_security.ssl.http.enabled", true)
					.put("opendistro_security.ssl.http.keystore_filepath",
							FileHelper.getAbsoluteFilePathFromClassPath("restapi/node-0-keystore.jks"))
					.put("opendistro_security.ssl.http.truststore_filepath",
							FileHelper.getAbsoluteFilePathFromClassPath("restapi/truststore.jks"));
		}
		return builder.build();
	}

	protected Map<String, String> jsonStringToMap(String json) throws JsonParseException, JsonMappingException, IOException {
		TypeReference<HashMap<String, String>> typeRef = new TypeReference<HashMap<String, String>>() {};
		return DefaultObjectMapper.objectMapper.readValue(json, typeRef);
	}

	protected static class TransportClientImpl extends TransportClient {

		public TransportClientImpl(Settings settings, Collection<Class<? extends Plugin>> plugins) {
			super(settings, plugins);
		}

		public TransportClientImpl(Settings settings, Settings defaultSettings, Collection<Class<? extends Plugin>> plugins) {
			super(settings, defaultSettings, plugins, null);
		}
	}

	protected static Collection<Class<? extends Plugin>> asCollection(Class<? extends Plugin>... plugins) {
		return Arrays.asList(plugins);
	}
}
