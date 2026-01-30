/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.support;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;

import org.junit.After;
import org.junit.Test;

import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.LdapUser;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SafeSerializationUtilsTest {

    @After
    public void clearCache() {
        SafeSerializationUtils.safeClassCache.clear();
    }

    @Test
    public void testSafeClasses() {
        assertTrue(SafeSerializationUtils.isSafeClass(String.class));
        assertTrue(SafeSerializationUtils.isSafeClass(InetSocketAddress.class));
        assertTrue(SafeSerializationUtils.isSafeClass(Pattern.class));
        assertTrue(SafeSerializationUtils.isSafeClass(User.class));
        assertTrue(SafeSerializationUtils.isSafeClass(SourceFieldsContext.class));
        assertTrue(SafeSerializationUtils.isSafeClass(LdapUser.class));
        assertTrue(SafeSerializationUtils.isSafeClass(LdapEntry.class));
        assertTrue(SafeSerializationUtils.isSafeClass(LdapAttribute.class));
    }

    @Test
    public void testSafeAssignableClasses() {
        assertTrue(SafeSerializationUtils.isSafeClass(InetAddress.class));
        assertTrue(SafeSerializationUtils.isSafeClass(Integer.class));
        assertTrue(SafeSerializationUtils.isSafeClass(ArrayList.class));
        assertTrue(SafeSerializationUtils.isSafeClass(HashMap.class));
        assertTrue(SafeSerializationUtils.isSafeClass(Enum.class));
    }

    @Test
    public void testArraysAreSafe() {
        assertTrue(SafeSerializationUtils.isSafeClass(String[].class));
        assertTrue(SafeSerializationUtils.isSafeClass(int[].class));
        assertTrue(SafeSerializationUtils.isSafeClass(Object[].class));
    }

    @Test
    public void testUnsafeClasses() {
        assertFalse(SafeSerializationUtils.isSafeClass(SafeSerializationUtilsTest.class));
        assertFalse(SafeSerializationUtils.isSafeClass(Runtime.class));
    }

    @Test
    public void testProhibitUnsafeClasses() {
        try {
            SafeSerializationUtils.prohibitUnsafeClasses(String.class);
        } catch (IOException e) {
            fail("Should not throw exception for safe class");
        }

        try {
            SafeSerializationUtils.prohibitUnsafeClasses(SafeSerializationUtilsTest.class);
            fail("Should throw exception for unsafe class");
        } catch (IOException e) {
            assertEquals("Unauthorized serialization attempt " + SafeSerializationUtilsTest.class.getName(), e.getMessage());
        }
    }

    @Test
    public void testInheritance() {
        class CustomArrayList extends ArrayList<String> {}
        assertTrue(SafeSerializationUtils.isSafeClass(CustomArrayList.class));

        class CustomMap extends HashMap<String, Integer> {}
        assertTrue(SafeSerializationUtils.isSafeClass(CustomMap.class));
    }

    @Test
    public void testCaching() {
        // First call should compute the result
        boolean result1 = SafeSerializationUtils.isSafeClass(String.class);
        assertTrue(result1);

        // Second call should use cached result
        boolean result2 = SafeSerializationUtils.isSafeClass(String.class);
        assertTrue(result2);

        // Verify that the cache was used (size should be 1)
        assertEquals(1, SafeSerializationUtils.safeClassCache.size());

        // Third call for a different class
        boolean result3 = SafeSerializationUtils.isSafeClass(Integer.class);
        assertTrue(result3);
        // Verify that the cache was updated
        assertEquals(2, SafeSerializationUtils.safeClassCache.size());
    }
}
