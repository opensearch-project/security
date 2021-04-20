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

package com.amazon.opendistroforelasticsearch.security;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class OpendistroSecurityRolesTests extends SingleClusterTest {

	@Test
	public void testOpenDistroSecurityRolesAnon() throws Exception {

		setup(Settings.EMPTY, new DynamicSecurityConfig()
				.setSecurityInternalUsers("internal_users_sr.yml")
				.setConfig("config_anon.yml"), Settings.EMPTY, true);

		RestHelper rh = nonSslRestHelper();

		HttpResponse resc = rh.executeGetRequest("_opendistro/_security/authinfo?pretty");
		Assert.assertTrue(resc.getBody().contains("anonymous"));
		Assert.assertFalse(resc.getBody().contains("xyz_sr"));
		Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

		resc = rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("sr_user", "nagilum"));
		Assert.assertTrue(resc.getBody().contains("sr_user"));
		Assert.assertTrue(resc.getBody().contains("xyz_sr"));
		Assert.assertFalse(resc.getBody().contains("opendistro_security_kibana_server"));
		Assert.assertTrue(resc.getBody().contains("backend_roles=[abc_ber]"));
		Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
	}

	@Test
	public void testOpenDistroSecurityRoles() throws Exception {

		setup(Settings.EMPTY, new DynamicSecurityConfig()
				.setSecurityRolesMapping("roles_mapping.yml")
				.setSecurityInternalUsers("internal_users_sr.yml"), Settings.EMPTY, true);

		RestHelper rh = nonSslRestHelper();
		rh.sendAdminCertificate = false;

		HttpResponse resc = rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("sr_user", "nagilum"));
		Assert.assertTrue(resc.getBody().contains("sr_user"));
		Assert.assertTrue(resc.getBody().contains("xyz_sr"));

		// Opendistro_security_roles cannot contain roles that don't exist.
		Assert.assertFalse(resc.getBody().contains("xyz_sr_non_existent"));

		// Opendistro_security_roles can contain reserved roles.
		Assert.assertTrue(resc.getBody().contains("xyz_sr_reserved"));

		// Opendistro_security_roles cannot contain roles that are hidden in rolesmapping.yml.
		Assert.assertFalse(resc.getBody().contains("xyz_sr_hidden"));

		Assert.assertTrue(resc.getBody().contains("backend_roles=[abc_ber]"));
		Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
	}

	@Test
	public void testOpenDistroSecurityRolesImpersonation() throws Exception {

		Settings settings = Settings.builder()
				.putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".sr_user", "sr_impuser")
				.build();

		setup(Settings.EMPTY, new DynamicSecurityConfig()
				.setSecurityInternalUsers("internal_users_sr.yml"), settings, true);

		RestHelper rh = nonSslRestHelper();

		HttpResponse resc = rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("sr_user", "nagilum"), new BasicHeader("opendistro_security_impersonate_as", "sr_impuser"));
		Assert.assertFalse(resc.getBody().contains("sr_user"));
		Assert.assertTrue(resc.getBody().contains("sr_impuser"));
		Assert.assertFalse(resc.getBody().contains("xyz_sr"));
		Assert.assertTrue(resc.getBody().contains("xyz_impsr"));
		Assert.assertTrue(resc.getBody().contains("backend_roles=[ert_ber]"));
		Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());

		resc = rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("sr_user", "nagilum"), new BasicHeader("opendistro_security_impersonate_as", "sr_impuser"));
		Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
	}
}

