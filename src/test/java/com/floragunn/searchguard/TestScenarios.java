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

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

public class TestScenarios extends AbstractScenarioTest {

    @Test
    public void testSearchOnlyAllowedMoreFilters() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        searchOnlyAllowedMoreFilters(getAuthSettings(wrongPassword, "ceo"), wrongPassword);
    }

    @Test
    public void testSimpleDlsScenario() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        simpleDlsScenario(getAuthSettings(wrongPassword, "ceo"));
    }

    @Test
    public void testSimpleFlsScenarioInclude() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        simpleFlsScenarioInclude(getAuthSettings(wrongPassword, "ceo"));
    }

    @Test
    public void testSimpleFlsScenarioExclude() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        simpleFlsScenarioExclude(getAuthSettings(wrongPassword, "ceo"));
    }

    @Test
    public void testSimpleFlsScenarioFields() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        simpleFlsScenarioFields(getAuthSettings(wrongPassword, "ceo"));
    }

    @Test
    public void testSimpleFlsScenarioPartialFields() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        simpleFlsScenarioPartialFields(getAuthSettings(wrongPassword, "ceo"));
    }

    @Test
    public void testSearchOnlyAllowedActionSessionsEnabled() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        final Settings settings = ImmutableSettings.builder().put(getAuthSettings(wrongPassword, "ceo"))
                .put(ConfigConstants.SEARCHGUARD_HTTP_ENABLE_SESSIONS, true).build();

        searchOnlyAllowedAction(settings, wrongPassword);
    }

    @Test
    public void testSearchOnlyAllowedAction() throws Exception {

        final boolean wrongPassword = false;
        username = "jacksonm";
        password = "secret";

        searchOnlyAllowedAction(getAuthSettings(wrongPassword, "ceo"), wrongPassword);
    }

    @Test
    public void testSearchOnlyAllowedActionFail() throws Exception {

        final boolean wrongPassword = true;
        username = "jacksonm";
        password = "secret";

        searchOnlyAllowedAction(getAuthSettings(wrongPassword, "ceo"), wrongPassword);
    }

    @Test
    public void testDlsLdapUserAttribute() throws Exception {
        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = ImmutableSettings
                .settingsBuilder()
                .put("searchguard.authentication.authorizer.impl", "com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator")
                .put("searchguard.authentication.authorizer.cache.enable", "true")
                .put("searchguard.authentication.authentication_backend.impl",
                        "com.floragunn.searchguard.authentication.backend.ldap.LDAPAuthenticationBackend")
                        .put("searchguard.authentication.authentication_backend.cache.enable", "true")
                        .putArray("searchguard.authentication.ldap.host", "localhost:" + ldapServerPort)
                        .put("searchguard.authentication.ldap.usersearch", "(uid={0})")
                .put("searchguard.authentication.ldap.username_attribute", "uid")
                        .put("searchguard.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                        .put("searchguard.authentication.authorization.ldap.rolename", "cn").build();

        dlsLdapUserAttribute(settings);
    }
}
