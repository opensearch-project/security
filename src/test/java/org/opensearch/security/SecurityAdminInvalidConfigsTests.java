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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.tools.SecurityAdmin;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

public class SecurityAdminInvalidConfigsTests extends SingleClusterTest {

	@Test
	public void testSecurityAdminDuplicateKey() throws Exception {
		final Settings settings = Settings.builder()
				.put("plugins.security.ssl.http.enabled",true)
				.put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
				.put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
				.build();
		setup(settings);

		final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

		List<String> argsAsList = new ArrayList<>();
		argsAsList.add("-ts");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
		argsAsList.add("-ks");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
		argsAsList.add("-p");
		argsAsList.add(String.valueOf(clusterInfo.httpPort));
		argsAsList.add("-cn");
		argsAsList.add(clusterInfo.clustername);
		argsAsList.add("-cd");
		argsAsList.add(new File("./src/test/resources/invalid_dupkey").getAbsolutePath());
		argsAsList.add("-nhnv");


		int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
		Assert.assertNotEquals(0, returnCode);

		RestHelper rh = restHelper();

		Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
	}

	@Test
	public void testSecurityAdminDuplicateKeyReload() throws Exception {
		testSecurityAdminDuplicateKey();

		final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

		List<String> argsAsList = new ArrayList<>();
		argsAsList.add("-ts");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
		argsAsList.add("-ks");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
		argsAsList.add("-p");
		argsAsList.add(String.valueOf(clusterInfo.httpPort));
		argsAsList.add("-cn");
		argsAsList.add(clusterInfo.clustername);
		argsAsList.add("-rl");
		argsAsList.add("-nhnv");


		int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
		Assert.assertEquals(0, returnCode);

		RestHelper rh = restHelper();

		Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
	}

	@Test
	public void testSecurityAdminDuplicateKeySingleFile() throws Exception {
		final Settings settings = Settings.builder()
				.put("plugins.security.ssl.http.enabled",true)
				.put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
				.put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
				.build();
		setup(settings);

		final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

		List<String> argsAsList = new ArrayList<>();
		argsAsList.add("-ts");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
		argsAsList.add("-ks");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
		argsAsList.add("-p");
		argsAsList.add(String.valueOf(clusterInfo.httpPort));
		argsAsList.add("-cn");
		argsAsList.add(clusterInfo.clustername);
		argsAsList.add("-f");
		argsAsList.add(new File("./src/test/resources/invalid_dupkey/roles_mapping.yml").getAbsolutePath());
		argsAsList.add("-t");
		argsAsList.add("rolesmapping");
		argsAsList.add("-nhnv");


		int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
		Assert.assertNotEquals(0, returnCode);

		RestHelper rh = restHelper();

		Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
	}

	@Test
	public void testSecurityAdminDuplicateKeyReloadSingleFile() throws Exception {
		testSecurityAdminDuplicateKeySingleFile();

		final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";

		List<String> argsAsList = new ArrayList<>();
		argsAsList.add("-ts");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
		argsAsList.add("-ks");
		argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
		argsAsList.add("-p");
		argsAsList.add(String.valueOf(clusterInfo.httpPort));
		argsAsList.add("-cn");
		argsAsList.add(clusterInfo.clustername);
		argsAsList.add("-rl");
		argsAsList.add("-nhnv");


		int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
		Assert.assertEquals(0, returnCode);

		RestHelper rh = restHelper();

		Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("_opendistro/_security/authinfo?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
		Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("*/_search?pretty", encodeBasicHeader("nagilum", "nagilum")).getStatusCode());
	}
}
