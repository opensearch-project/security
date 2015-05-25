/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard;

import java.net.URL;

import net.sourceforge.spnego.SpnegoHttpURLConnection;

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.tests.DummyLoginModule;
import com.floragunn.searchguard.util.SecurityUtil;

public class SfSpNegoTest extends AbstractUnitTest {

    @Test
    public void sfSpNegoTest() throws Exception {

        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .putArray("searchguard.restactionfilter.names", "readonly")
                .putArray("searchguard.restactionfilter.readonly.allowed_actions", "RestSearchAction")

                .put("searchguard.authentication.http_authenticator.impl",
                        "com.floragunn.searchguard.authentication.http.spnego.HTTPSpnegoAuthenticator")
                        .put("searchguard.authentication.spnego.login_config_filepath", System.getProperty("java.security.auth.login.config"))
                        .put("searchguard.authentication.spnego.krb5_config_filepath", System.getProperty("java.security.krb5.conf"))

                        .put("searchguard.authentication.authorizer.impl", "com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator")
                        .put("searchguard.authentication.authorizer.cache.enable", "false")
                        .put("searchguard.authentication.authentication_backend.impl",
                                "com.floragunn.searchguard.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                                .put("searchguard.authentication.authentication_backend.cache.enable", "false")
                                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                                .put("searchguard.authentication.authorization.ldap.rolename", "cn")

                                .build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        DummyLoginModule.username = "hnelson";
        DummyLoginModule.password = "secret".toCharArray();

        final net.sourceforge.spnego.SpnegoHttpURLConnection hcon = new SpnegoHttpURLConnection("com.sun.security.jgss.krb5.initiate",
                "hnelson@EXAMPLE.COM", "secret");

        hcon.requestCredDeleg(true);

        hcon.connect(new URL(getServerUri(false) + "/public/_search"));

        Assert.assertEquals(200, hcon.getResponseCode());

    }

}
