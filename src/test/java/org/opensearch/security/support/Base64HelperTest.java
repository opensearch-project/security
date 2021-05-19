/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package org.opensearch.security.support;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.user.User;

import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;

import com.google.common.io.BaseEncoding;

import static org.opensearch.security.support.Base64Helper.deserializeObject;
import static org.opensearch.security.support.Base64Helper.serializeObject;

public class Base64HelperTest {

    private static final class NotSafeSerializable implements Serializable {
        private static final long serialVersionUID = 5135559266828470092L;
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
        Integer integer = Integer.valueOf(0);
        Assert.assertEquals(integer, ds(integer));
    }

    @Test
    public void testDouble() {
        Double number = Double.valueOf(0.);
        Assert.assertEquals(number, ds(number));
    }

    @Test
    public void testInetSocketAddress() {
        InetSocketAddress inetSocketAddress = new InetSocketAddress(0);
        Assert.assertEquals(inetSocketAddress, ds(inetSocketAddress));
    }

    @Test
    public void testPattern() {
        Pattern pattern = Pattern.compile(".*");
        Assert.assertEquals(pattern.pattern(), ((Pattern) ds(pattern)).pattern());
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
        HashMap map = new HashMap();
        Assert.assertEquals(map, ds(map));
    }

    @Test
    public void testArrayList() {
        ArrayList list = new ArrayList();
        Assert.assertEquals(list, ds(list));
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeSerializable() {
        serializeObject(new NotSafeSerializable());
    }

    @Test(expected = OpenSearchException.class)
    public void notSafeDeserializable() throws Exception {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(new NotSafeSerializable());
        }
        deserializeObject(BaseEncoding.base64().encode(bos.toByteArray()));
    }
}
