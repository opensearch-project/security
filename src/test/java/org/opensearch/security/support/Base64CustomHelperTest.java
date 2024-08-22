/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.support;

import java.io.Serializable;
import java.net.InetSocketAddress;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.security.auth.UserInjector;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.LdapUser;
import org.ldaptive.LdapEntry;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.support.Base64CustomHelper.deserializeObject;
import static org.opensearch.security.support.Base64CustomHelper.serializeObject;

public class Base64CustomHelperTest {

    private static final class NotSafeStreamable implements Serializable {
        private static final long serialVersionUID = 5135559266828470092L;
    }

    private static final class NotSafeWriteable implements Writeable, Serializable {
        @Override
        public void writeTo(StreamOutput out) {

        }
    }

    private static Serializable ds(Serializable s) {
        return deserializeObject(serializeObject(s));
    }

    @Test
    public void testString() {
        String string = "string";
        assertThat(ds(string), is(string));
    }

    @Test
    public void testInteger() {
        Integer integer = 0;
        assertThat(ds(integer), is(integer));
    }

    @Test
    public void testDouble() {
        Double number = 0.;
        assertThat(ds(number), is(number));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        assertThat(ds(inetSocketAddress), is(inetSocketAddress));
    }

    @Test
    public void testUser() {
        User user = new User("user");
        assertThat(ds(user), is(user));
    }

    @Test
    public void testSourceFieldsContext() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        assertThat(ds(sourceFieldsContext).toString(), is(sourceFieldsContext.toString()));
    }

    @Test
    public void testHashMap() {
        HashMap<String, String> map = new HashMap<>() {
            {
                put("key", "value");
            }
        };
        assertThat(ds(map), is(map));
    }

    @Test
    public void testArrayList() {
        ArrayList<String> list = new ArrayList<>() {
            {
                add("value");
            }
        };
        assertThat(ds(list), is(list));
    }

    @Test
    public void testLdapUser() {
        LdapUser ldapUser = new LdapUser(
            "username",
            "originalusername",
            new LdapEntry("dn"),
            new AuthCredentials("originalusername", "12345"),
            34,
            WildcardMatcher.ANY
        );
        assertThat(ds(ldapUser), is(ldapUser));
    }

    @Test
    public void testGetWriteableClassID() {
        // a need to make a change in this test signifies a breaking change in security plugin's custom serialization
        // format
        assertThat(Base64CustomHelper.getWriteableClassID(User.class), is(Integer.valueOf(1)));
        assertThat(Base64CustomHelper.getWriteableClassID(LdapUser.class), is(Integer.valueOf(2)));
        assertThat(Base64CustomHelper.getWriteableClassID(UserInjector.InjectedUser.class), is(Integer.valueOf(3)));
        assertThat(Base64CustomHelper.getWriteableClassID(SourceFieldsContext.class), is(Integer.valueOf(4)));
    }

    @Test
    public void testInjectedUser() {
        UserInjector.InjectedUser injectedUser = new UserInjector.InjectedUser("username");

        // for custom serialization, we expect InjectedUser to be returned on deserialization
        UserInjector.InjectedUser deserializedInjecteduser = (UserInjector.InjectedUser) ds(injectedUser);
        assertThat(deserializedInjecteduser, is(injectedUser));
        Assert.assertTrue(deserializedInjecteduser.isInjected());
    }

    @Test(expected = OpenSearchException.class)
    public void testNotSafeStreamable() {
        Base64JDKHelper.serializeObject(new NotSafeStreamable());
    }

    @Test(expected = OpenSearchException.class)
    public void testNotSafeWriteable() {
        Base64JDKHelper.serializeObject(new NotSafeWriteable());
    }

    @Test(expected = OpenSearchException.class)
    public void testNotSafeGeneric() {
        HashMap<Integer, ZonedDateTime> map = new HashMap<>();
        map.put(1, ZonedDateTime.now());
        map.put(2, ZonedDateTime.now());
        Base64JDKHelper.serializeObject(map);
    }

}
