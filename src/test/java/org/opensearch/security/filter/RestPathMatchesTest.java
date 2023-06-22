package org.opensearch.security.filter;

import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

public class RestPathMatchesTest {
    Method restPathMatches;
    SecurityRestFilter securityRestFilter;

    @Before
    public void setUp() throws NoSuchMethodException {
        securityRestFilter = mock(SecurityRestFilter.class);
        restPathMatches = SecurityRestFilter.class.getDeclaredMethod("restPathMatches", String.class, String.class);
        restPathMatches.setAccessible(true);
    }

    @Test
    public void testExactMatch() throws InvocationTargetException, IllegalAccessException {
        String requestPath = "_plugins/security/api/x/y";
        String handlerPath = "_plugins/security/api/x/y";
        assertTrue((Boolean) restPathMatches.invoke(securityRestFilter, requestPath, handlerPath));
    }

    @Test
    public void testPartialMatch() throws InvocationTargetException, IllegalAccessException {
        String requestPath = "_plugins/security/api/x/y";
        String handlerPath = "_plugins/security/api/x/z";
        assertFalse((Boolean) restPathMatches.invoke(securityRestFilter, requestPath, handlerPath));
    }

    @Test
    public void testNamedParamsMatch() throws InvocationTargetException, IllegalAccessException {
        String requestPath = "_plugins/security/api/123/y";
        String handlerPath = "_plugins/security/api/{id}/y";
        assertTrue((Boolean) restPathMatches.invoke(securityRestFilter, requestPath, handlerPath));
    }

    @Test
    public void testDifferentPathLength() throws InvocationTargetException, IllegalAccessException {
        String requestPath = "_plugins/security/api/x/y/z";
        String handlerPath = "_plugins/security/api/x/y";
        assertFalse((Boolean) restPathMatches.invoke(securityRestFilter, requestPath, handlerPath));
    }

    @Test
    public void testDifferentPathSegments() throws InvocationTargetException, IllegalAccessException {
        String requestPath = "_plugins/security/api/a/b";
        String handlerPath = "_plugins/security/api/x/y";
        assertFalse((Boolean) restPathMatches.invoke(securityRestFilter, requestPath, handlerPath));
    }
}

