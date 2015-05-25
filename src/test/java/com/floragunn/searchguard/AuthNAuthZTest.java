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

import java.util.Arrays;
import java.util.Collection;

import org.elasticsearch.common.settings.Settings;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import com.floragunn.searchguard.tests.DummyLoginModule;
import com.floragunn.searchguard.util.SecurityUtil;

@RunWith(Parameterized.class)
public class AuthNAuthZTest extends AbstractScenarioTest {

    @Parameter
    public boolean cacheEnabled;

    @Parameter(value = 1)
    public boolean wrongPwd;

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] { { true, true }, { false, false }, { false, true }, { true, false } });
    }

    @Test
    public void testLdapAuth() throws Exception {
        //Basic/Ldap/Ldap
        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("searchguard.authentication.authorizer.impl", "com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator")
                .put("searchguard.authentication.authentication_backend.impl",
                        "com.floragunn.searchguard.authentication.backend.ldap.LDAPAuthenticationBackend")
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.username_attribute", "uid")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn").build();

        username = "jacksonm";
        password = "secret" + (wrongPwd ? "-wrong" : "");

        searchOnlyAllowed(settings, wrongPwd);
    }

    @Test
    public void testProxyAuth() throws Exception {
        //Proxy/Always/Ldap
        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("searchguard.authentication.http_authenticator.impl",
                        "com.floragunn.searchguard.authentication.http.proxy.HTTPProxyAuthenticator")
                        .putArray("searchguard.authentication.proxy.trusted_ips", "*")
                        .put("searchguard.authentication.authorizer.impl", "com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator")
                        .put("searchguard.authentication.authentication_backend.impl",
                                "com.floragunn.searchguard.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.username_attribute", "uid")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn").build();

        this.headers.put("X-Authenticated-User", "jacksonm" + (wrongPwd ? "-wrong" : ""));

        searchOnlyAllowed(settings, wrongPwd);
    }

    @Test
    public void testSpnegoAuth() throws Exception {
        //SPNEGO/Always/Ldap
        useSpnego = true;

        startLDAPServer();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("searchguard.authentication.http_authenticator.impl",
                        "com.floragunn.searchguard.authentication.http.spnego.HTTPSpnegoAuthenticator")
                .put("searchguard.authentication.spnego.login_config_filepath", System.getProperty("java.security.auth.login.config"))
                .put("searchguard.authentication.spnego.krb5_config_filepath", System.getProperty("java.security.krb5.conf"))
                .put("searchguard.authentication.authorizer.impl", "com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator")
                .put("searchguard.authentication.authentication_backend.impl",
                        "com.floragunn.searchguard.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("searchguard.authentication.authorization.ldap.rolename", "cn").build();

        DummyLoginModule.username = "hnelson";
        DummyLoginModule.password = ("secret" + (wrongPwd ? "-wrong" : "")).toCharArray();

        searchOnlyAllowed(settings, wrongPwd);
    }

}
