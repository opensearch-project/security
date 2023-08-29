/*
 * Copyright 2015-2017 floragunn GmbH
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

package org.opensearch.security;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.tools.SecurityAdmin;

public class SecurityAdminTests extends SingleClusterTest {

    @Test
    public void testSecurityAdmin() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, null, settings, false);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        RestHelper rh = restHelper();

        Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
    }

    @Test
    public void testSecurityAdminInvalidCert() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, null, settings, false);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        RestHelper rh = restHelper();

        Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_plugins/_security/health?pretty")).getStatusCode());

        argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "spock-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("--diagnose");
        argsAsList.add("-nhnv");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(-1, returnCode);

        Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_plugins/_security/health?pretty")).getStatusCode());

        argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "node-0-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-nhnv");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(-1, returnCode);

        Assert.assertEquals(HttpStatus.SC_OK, (rh.executeGetRequest("_plugins/_security/health?pretty")).getStatusCode());
    }

    @Test
    public void testSecurityAdminV6Update() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, null, settings, false);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        addDirectoryPath(argsAsList, new File("./legacy/securityconfig_v6").getAbsolutePath());
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        RestHelper rh = restHelper();

        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, rh.executeGetRequest("_opendistro/_security/health?pretty").getStatusCode());
    }

    @Test
    public void testSecurityAdminRegularUpdate() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, null, settings, true);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        RestHelper rh = restHelper();
        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }

    @Test
    public void testSecurityAdminSingularV7Updates() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File(TEST_RESOURCE_RELATIVE_PATH + "config.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("config");
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File(TEST_RESOURCE_RELATIVE_PATH + "roles_mapping.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("rolesmapping");
        argsAsList.add("-nhnv");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File(TEST_RESOURCE_RELATIVE_PATH + "tenants.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("tenants");
        argsAsList.add("-nhnv");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        RestHelper rh = restHelper();
        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }

    @Test
    public void testSecurityAdminSingularV6Updates() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File(TEST_RESOURCE_RELATIVE_PATH + "legacy/securityconfig_v6/config.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("config");
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        RestHelper rh = restHelper();
        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }

    @Test
    public void testSecurityAdminInvalidYml() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "roles_invalidxcontent.yml"))
                .toFile()
                .getAbsolutePath()
        );
        argsAsList.add("-t");
        argsAsList.add("roles");
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        RestHelper rh = restHelper();
        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }

    @Test
    public void testSecurityAdminReloadInvalidConfig() throws Exception {
        final Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true);
        final RestHelper rh = restHelper(); // ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        rh.executePutRequest(".opendistro_security/_doc/roles", FileHelper.loadFile("roles_invalidxcontent.yml"));
        Assert.assertEquals(
            HttpStatus.SC_OK,
            rh.executePutRequest(".opendistro_security/_doc/roles", "{\"roles\":\"dummy\"}").getStatusCode()
        );

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-rl");
        argsAsList.add("-nhnv");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        HttpResponse res;

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }

    @Test
    public void testSecurityAdminValidateConfig() throws Exception {
        List<String> argsAsList = new ArrayList<>();
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-vc");

        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File(PROJECT_ROOT_RELATIVE_PATH + "src/test/resources/roles.yml").getAbsolutePath());
        argsAsList.add("-vc");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File(PROJECT_ROOT_RELATIVE_PATH + "src/main/resources/static_config/static_roles.yml").getAbsolutePath());
        argsAsList.add("-vc");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(
            new File(PROJECT_ROOT_RELATIVE_PATH + "src/main/resources/static_config/static_action_groups.yml").getAbsolutePath()
        );
        argsAsList.add("-vc");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File(PROJECT_ROOT_RELATIVE_PATH + "src/main/resources/static_config/static_tenants.yml").getAbsolutePath());
        argsAsList.add("-vc");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(TEST_RESOURCE_ABSOLUTE_PATH + "roles.yml");
        argsAsList.add("-vc");
        argsAsList.add("-t");
        argsAsList.add("config");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        argsAsList.add("-ks");
        argsAsList.add(TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-vc");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH + "legacy/securityconfig_v6");
        argsAsList.add("-vc");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH + "legacy/securityconfig_v6");
        argsAsList.add("-vc");
        argsAsList.add("6");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        argsAsList = new ArrayList<>();
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-vc");
        argsAsList.add("8");

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);
    }

    @Test
    public void testIsLegacySecurityIndexOnV7Index() throws Exception {
        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .build();
        setup(Settings.EMPTY, null, settings, false);

        final String prefix = getResourceFolder() == null ? "" : getResourceFolder() + "/";

        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "truststore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-ks");
        argsAsList.add(
            Objects.requireNonNull(FileHelper.getAbsoluteFilePathFromClassPath(prefix + "kirk-keystore.jks")).toFile().getAbsolutePath()
        );
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.httpPort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        addDirectoryPath(argsAsList, TEST_RESOURCE_ABSOLUTE_PATH);
        argsAsList.add("-nhnv");

        // Execute first time to create the index
        int returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        PrintStream old = System.out;
        System.setOut(ps);

        returnCode = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);

        System.out.flush();
        System.setOut(old);
        String standardOut = baos.toString();
        String legacyIndexOutput = "Legacy index '"
            + ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX
            + "' (ES 6) detected (or forced). You should migrate the configuration!";
        Assert.assertFalse(standardOut.contains(legacyIndexOutput));
    }

    private void addDirectoryPath(final List<String> args, final String path) {
        args.add("-cd");
        args.add(path);
    }
}
