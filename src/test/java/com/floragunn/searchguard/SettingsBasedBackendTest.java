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
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.simple.SettingsBasedAuthenticationBackend;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.authorization.simple.SettingsBasedAuthorizator;

public class SettingsBasedBackendTest extends AbstractUnitTest {

    @Test
    public void testSimple() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "vulcan").build();

        Assert.assertEquals("spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "vulcan".toCharArray()))
                .getName());

    }

    @Test
    public void testSimpleRoles() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "vulcan").build();

        Assert.assertEquals("spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "vulcan".toCharArray()))
                .getName());

        final User user = new User("spock");
        final Authorizator authorizator = new SettingsBasedAuthorizator(settings);
        authorizator.fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(3, user.getRoles().size());

    }

    @Test
    public void testDigestMd5() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "vulcan")
                .put("searchguard.authentication.settingsdb.digest", "md5").build();

        Assert.assertEquals(
                "spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(
                        new AuthCredentials("spock", "0c94ea3ecdd57ac44984589682e4be05".toCharArray())).getName());

    }

    @Test
    public void testDigestSha1() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "vulcan")
                .put("searchguard.authentication.settingsdb.digest", "sha1").build();

        Assert.assertEquals(
                "spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(
                        new AuthCredentials("spock", "966032eab6276624119a49080934e3936d2976f7".toCharArray())).getName());

    }

    @Test(expected = AuthException.class)
    public void testDigestSha1Fail() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "vulcan")
                .put("searchguard.authentication.settingsdb.digest", "sha1").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "vulcan".toCharArray()));

    }

    @Test(expected = AuthException.class)
    public void testFailUser() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "vulcan").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("picard", "secret".toCharArray()));

    }

    @Test(expected = AuthException.class)
    public void testFailPassword() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "vulcan").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "secret".toCharArray()));

    }

}
