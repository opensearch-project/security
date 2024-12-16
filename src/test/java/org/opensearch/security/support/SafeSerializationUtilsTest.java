package org.opensearch.security.support;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.regex.Pattern;

import org.junit.Test;

import org.opensearch.security.auth.UserInjector;
import org.opensearch.security.user.User;

import com.amazon.dlic.auth.ldap.LdapUser;
import org.ldaptive.AbstractLdapBean;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchEntry;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SafeSerializationUtilsTest {

    @Test
    public void testSafeClasses() {
        assertTrue(SafeSerializationUtils.isSafeClass(String.class));
        assertTrue(SafeSerializationUtils.isSafeClass(InetSocketAddress.class));
        assertTrue(SafeSerializationUtils.isSafeClass(Pattern.class));
        assertTrue(SafeSerializationUtils.isSafeClass(User.class));
        assertTrue(SafeSerializationUtils.isSafeClass(UserInjector.InjectedUser.class));
        assertTrue(SafeSerializationUtils.isSafeClass(SourceFieldsContext.class));
        assertTrue(SafeSerializationUtils.isSafeClass(LdapUser.class));
        assertTrue(SafeSerializationUtils.isSafeClass(SearchEntry.class));
        assertTrue(SafeSerializationUtils.isSafeClass(LdapEntry.class));
        assertTrue(SafeSerializationUtils.isSafeClass(AbstractLdapBean.class));
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
}
