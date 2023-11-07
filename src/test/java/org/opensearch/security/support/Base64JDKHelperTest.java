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

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;

import com.google.common.io.BaseEncoding;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.security.auth.UserInjector;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.LdapUser;
import org.ldaptive.LdapEntry;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThrows;

public class Base64JDKHelperTest {
    private static final class NotSafeSerializable implements Serializable {
        private static final long serialVersionUID = 5135559266828470092L;
    }

    private static Serializable ds(Serializable s) {
        return Base64JDKHelper.deserializeObject(Base64JDKHelper.serializeObject(s));
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
        Double number = 0.0;
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
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "value");
        Assert.assertEquals(map, ds(map));
    }

    @Test
    public void testArrayList() {
        ArrayList<String> list = new ArrayList<>();
        list.add("value");
        Assert.assertEquals(list, ds(list));
    }

    @Test
    public void notSafeSerializable() {
        final OpenSearchException exception = assertThrows(
            OpenSearchException.class,
            () -> Base64JDKHelper.serializeObject(new NotSafeSerializable())
        );
        assertThat(exception.getMessage(), containsString("NotSafeSerializable is not serializable"));
    }

    @Test
    public void notSafeDeserializable() throws Exception {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(new NotSafeSerializable());
        }
        final OpenSearchException exception = assertThrows(
            OpenSearchException.class,
            () -> Base64JDKHelper.deserializeObject(BaseEncoding.base64().encode(bos.toByteArray()))
        );
        assertThat(exception.getMessage(), containsString("Unauthorized deserialization attempt"));
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
    public void testInjectedUser() {
        UserInjector.InjectedUser injectedUser = new UserInjector.InjectedUser("username");

        // we expect to get User object when deserializing InjectedUser via JDK serialization
        User user = new User("username");
        User deserializedUser = (User) ds(injectedUser);
        Assert.assertEquals(user, deserializedUser);
        Assert.assertTrue(deserializedUser.isInjected());
    }
}
