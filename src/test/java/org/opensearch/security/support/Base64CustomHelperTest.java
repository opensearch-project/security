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
        Assert.assertEquals(string, ds(string));
    }

    @Test
    public void testInteger() {
        Integer integer = 0;
        Assert.assertEquals(integer, ds(integer));
    }

    @Test
    public void testDouble() {
        Double number = 0.;
        Assert.assertEquals(number, ds(number));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, ds(inetSocketAddress));
    }

    @Test
    public void testUser() {
        User user = new User("user");
        Assert.assertEquals(user, ds(user));
    }

    @Test
    public void testSourceFieldsContext() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        Assert.assertEquals(sourceFieldsContext.toString(), ds(sourceFieldsContext).toString());
    }

    @Test
    public void testHashMap() {
        HashMap<String, String> map = new HashMap<>() {
            {
                put("key", "value");
            }
        };
        Assert.assertEquals(map, ds(map));
    }

    @Test
    public void testArrayList() {
        ArrayList<String> list = new ArrayList<>() {
            {
                add("value");
            }
        };
        Assert.assertEquals(list, ds(list));
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
        Assert.assertEquals(ldapUser, ds(ldapUser));
    }

    @Test
    public void testGetWriteableClassID() {
        // a need to make a change in this test signifies a breaking change in security plugin's custom serialization
        // format
        Assert.assertEquals(Integer.valueOf(1), Base64CustomHelper.getWriteableClassID(User.class));
        Assert.assertEquals(Integer.valueOf(2), Base64CustomHelper.getWriteableClassID(LdapUser.class));
        Assert.assertEquals(Integer.valueOf(3), Base64CustomHelper.getWriteableClassID(UserInjector.InjectedUser.class));
        Assert.assertEquals(Integer.valueOf(4), Base64CustomHelper.getWriteableClassID(SourceFieldsContext.class));
    }

    @Test
    public void testInjectedUser() {
        UserInjector.InjectedUser injectedUser = new UserInjector.InjectedUser("username");

        // for custom serialization, we expect InjectedUser to be returned on deserialization
        UserInjector.InjectedUser deserializedInjecteduser = (UserInjector.InjectedUser) ds(injectedUser);
        Assert.assertEquals(injectedUser, deserializedInjecteduser);
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
