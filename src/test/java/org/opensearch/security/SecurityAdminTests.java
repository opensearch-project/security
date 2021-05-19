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

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.opensearch.security.tools.SecurityAdmin;
import org.apache.http.HttpStatus;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

public class SecurityAdminTests extends SingleClusterTest {
    
    @Test
    public void testSecurityAdmin() throws Exception {
        setup(Settings.EMPTY, null, Settings.EMPTY, false);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-cd");
        argsAsList.add(new File("src/test/resources/").getAbsolutePath());
        argsAsList.add("-nhnv");
        
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
    }
    
    @Test
    public void testSecurityAdminV6Update() throws Exception {
        setup(Settings.EMPTY, null, Settings.EMPTY, false);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-cd");
        argsAsList.add(new File("./legacy/securityconfig_v6").getAbsolutePath());
        argsAsList.add("-nhnv");
        
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        //System.out.println(res.getBody());
        //assertContains(res, "*UP*");
        //assertContains(res, "*strict*");
        //assertNotContains(res, "*DOWN*");
    }
    
    @Test
    public void testSecurityAdminRegularUpdate() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-cd");
        argsAsList.add(new File("src/test/resources/").getAbsolutePath());
        argsAsList.add("-nhnv");
        
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }
    
    @Test
    public void testSecurityAdminSingularV7Updates() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File("./securityconfig/config.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("config");
        argsAsList.add("-nhnv");
        
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File("./securityconfig/roles_mapping.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("rolesmapping");
        argsAsList.add("-nhnv");
        
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File("./securityconfig/tenants.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("tenants");
        argsAsList.add("-nhnv");
        
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }
    
    @Test
    public void testSecurityAdminSingularV6Updates() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(new File("./legacy/securityconfig_v6/config.yml").getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("config");
        argsAsList.add("-nhnv");
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);

        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }
    
    @Test
    public void testSecurityAdminInvalidYml() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY, true);
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-f");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"roles_invalidxcontent.yml").toFile().getAbsolutePath());
        argsAsList.add("-t");
        argsAsList.add("roles");
        argsAsList.add("-nhnv");
        
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_opendistro/_security/health?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }
    
    @Test
    public void testSecurityAdminReloadInvalidConfig() throws Exception {
        final Settings settings = Settings.builder()
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("opendistro_security.ssl.http.enabled",true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendAdminCertificate = true;
        rh.keystore = "kirk-keystore.jks";
        System.out.println(rh.executePutRequest(".opendistro_security/"+getType()+"/roles", FileHelper.loadFile("roles_invalidxcontent.yml")).getBody());;
        Assert.assertEquals(HttpStatus.SC_OK, rh.executePutRequest(".opendistro_security/"+getType()+"/roles", "{\"roles\":\"dummy\"}").getStatusCode());
        
        
        final String prefix = getResourceFolder()==null?"":getResourceFolder()+"/";
        
        List<String> argsAsList = new ArrayList<>();
        argsAsList.add("-ts");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"truststore.jks").toFile().getAbsolutePath());
        argsAsList.add("-ks");
        argsAsList.add(FileHelper.getAbsoluteFilePathFromClassPath(prefix+"kirk-keystore.jks").toFile().getAbsolutePath());
        argsAsList.add("-p");
        argsAsList.add(String.valueOf(clusterInfo.nodePort));
        argsAsList.add("-cn");
        argsAsList.add(clusterInfo.clustername);
        argsAsList.add("-rl");
        argsAsList.add("-nhnv");
        
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
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
        argsAsList.add("-cd");
        argsAsList.add(new File("src/test/resources/").getAbsolutePath());
        argsAsList.add("-vc");
        
        int returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File("src/test/resources/roles.yml").getAbsolutePath());
        argsAsList.add("-vc");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File("./src/main/resources/static_config/static_roles.yml").getAbsolutePath());
        argsAsList.add("-vc");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File("./src/main/resources/static_config/static_action_groups.yml").getAbsolutePath());
        argsAsList.add("-vc");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File("./src/main/resources/static_config/static_tenants.yml").getAbsolutePath());
        argsAsList.add("-vc");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-f");
        argsAsList.add(new File("src/test/resources/roles.yml").getAbsolutePath());
        argsAsList.add("-vc");
        argsAsList.add("-t");
        argsAsList.add("config");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-ks");
        argsAsList.add(new File("src/test/resources/").getAbsolutePath());
        argsAsList.add("-vc");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-cd");
        argsAsList.add(new File("./legacy/securityconfig_v6").getAbsolutePath());
        argsAsList.add("-vc");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-cd");
        argsAsList.add(new File("./legacy/securityconfig_v6").getAbsolutePath());
        argsAsList.add("-vc");
        argsAsList.add("6");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertEquals(0, returnCode);
        
        argsAsList = new ArrayList<>();
        argsAsList.add("-cd");
        argsAsList.add(new File("src/test/resources/").getAbsolutePath());
        argsAsList.add("-vc");
        argsAsList.add("8");
        
        returnCode  = SecurityAdmin.execute(argsAsList.toArray(new String[0]));
        Assert.assertNotEquals(0, returnCode);
    }
}
