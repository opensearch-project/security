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
import java.util.regex.Pattern;

import com.google.common.io.BaseEncoding;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.security.user.User;

import static org.opensearch.security.support.Base64Helper.deserializeObjectJDK;
import static org.opensearch.security.support.Base64Helper.deserializeObjectProto;
import static org.opensearch.security.support.Base64Helper.serializeObjectJDK;
import static org.opensearch.security.support.Base64Helper.serializeObjectProto;

public class Base64HelperTest {

    private static final class NotSafeSerializable implements Serializable {
        private static final long serialVersionUID = 5135559266828470092L;
    }

    private static Serializable dsJDK(Serializable s) {
        return deserializeObjectJDK(serializeObjectJDK(s));
    }

    private static Serializable dsProto(Serializable s) {
        return deserializeObjectProto(serializeObjectProto(s));
    }

    @Test
    public void testString() {
        String string = "string";
        Assert.assertEquals(string, dsJDK(string));
        Assert.assertEquals(string, dsProto(string));
    }

    @Test
    public void testInteger() {
        Integer integer = Integer.valueOf(0);
        Assert.assertEquals(integer, dsJDK(integer));
        Assert.assertEquals(integer, dsProto(integer));
    }

    @Test
    public void testDouble() {
        Double number = Double.valueOf(0.);
        Assert.assertEquals(number, dsJDK(number));
        Assert.assertEquals(number, dsProto(number));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, dsJDK(inetSocketAddress));
        Assert.assertEquals(inetSocketAddress, dsProto(inetSocketAddress));

    }

    @Test
    public void testPattern() {
        Pattern pattern = Pattern.compile(".*");
        Assert.assertEquals(pattern.pattern(), ((Pattern) dsJDK(pattern)).pattern());
        Assert.assertEquals(pattern.pattern(), ((Pattern) dsProto(pattern)).pattern());

    }

    @Test
    public void testUser() {
        User user = new User("user");
        Assert.assertEquals(user, dsJDK(user));
        Assert.assertEquals(user, dsProto(user));
    }

    @Test
    public void testSourceFieldsContext() {
        SourceFieldsContext sourceFieldsContext = new SourceFieldsContext(new SearchRequest(""));
        Assert.assertEquals(sourceFieldsContext.toString(), dsJDK(sourceFieldsContext).toString());
        Assert.assertEquals(sourceFieldsContext.toString(), dsProto(sourceFieldsContext).toString());

    }

    @Test
    public void testHashMap() {
        HashMap map = new HashMap();
        Assert.assertEquals(map, dsJDK(map));
        Assert.assertEquals(map, dsProto(map));
    }

    @Test
    public void testArrayList() {
        ArrayList list = new ArrayList();
        Assert.assertEquals(list, dsJDK(list));
        Assert.assertEquals(list, dsProto(list));
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeSerializable() {
        serializeObjectJDK(new NotSafeSerializable());
        serializeObjectProto(new NotSafeSerializable());
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeDeserializable() throws Exception {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(new NotSafeSerializable());
        }
        deserializeObjectJDK(BaseEncoding.base64().encode(bos.toByteArray()));
        deserializeObjectProto(BaseEncoding.base64().encode(bos.toByteArray()));
    }
}
