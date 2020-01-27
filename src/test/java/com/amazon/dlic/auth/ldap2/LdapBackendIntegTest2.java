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

package com.amazon.dlic.auth.ldap2;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.common.settings.Settings;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.amazon.dlic.auth.ldap.srv.EmbeddedLDAPServer;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class LdapBackendIntegTest2 extends SingleClusterTest {

    private static EmbeddedLDAPServer ldapServer = null;

    private static int ldapPort;
    private static int ldapsPort;

    @BeforeClass
    public static void startLdapServer() throws Exception {
        ldapServer = new EmbeddedLDAPServer();
        ldapServer.start();
        ldapServer.applyLdif("base.ldif");
        ldapPort = ldapServer.getLdapPort();
        ldapsPort = ldapServer.getLdapsPort();
    }

    @Override
    protected String getResourceFolder() {
        return "ldap";
    }

    @Test
    public void testIntegLdapAuthenticationSSL() throws Exception {
        String securityConfigAsYamlString = FileHelper.loadFile("ldap/config_ldap2.yml");
        securityConfigAsYamlString = securityConfigAsYamlString.replace("${ldapsPort}", String.valueOf(ldapsPort));
        System.out.println(securityConfigAsYamlString);
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfigAsYamlString(securityConfigAsYamlString), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("jacksonm", "secret")).getStatusCode());
    }

    @Test
    public void testIntegLdapAuthenticationSSLFail() throws Exception {
        String securityConfigAsYamlString = FileHelper.loadFile("ldap/config_ldap2.yml");
        securityConfigAsYamlString = securityConfigAsYamlString.replace("${ldapsPort}", String.valueOf(ldapsPort));
        System.out.println(securityConfigAsYamlString);
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfigAsYamlString(securityConfigAsYamlString), Settings.EMPTY);
        final RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, rh.executeGetRequest("", encodeBasicHeader("wrong", "wrong")).getStatusCode());
    }

    @Test
    public void testAttributesWithImpersonation() throws Exception {
        String securityConfigAsYamlString = FileHelper.loadFile("ldap/config_ldap2.yml");
        securityConfigAsYamlString = securityConfigAsYamlString.replace("${ldapsPort}", String.valueOf(ldapsPort));
        final Settings settings = Settings.builder()
                .putList(ConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".cn=Captain Spock,ou=people,o=TEST", "*")
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setConfigAsYamlString(securityConfigAsYamlString), settings);
        final RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res=rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader("opendistro_security_impersonate_as", "jacksonm")
                ,encodeBasicHeader("spock", "spocksecret"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("ldap.dn"));
        Assert.assertTrue(res.getBody().contains("attr.ldap.entryDN"));
        Assert.assertTrue(res.getBody().contains("attr.ldap.subschemaSubentry"));

    }


    @AfterClass
    public static void tearDownLdap() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }
}
