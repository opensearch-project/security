package org.opensearch.security.identity;

import org.junit.Before;
import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class SecuritySubjectTest {

    private SecuritySubject securitySubject;
    private ThreadContext threadContext;

    @Before
    public void setUp() {
        securitySubject = new SecuritySubject();
        threadContext = new ThreadContext(Settings.EMPTY);
        securitySubject.setThreadContext(threadContext);
    }

    @Test
    public void testGetPrincipalWhenThreadContextIsNull() {
        securitySubject.setThreadContext(null);
        Principal principal = securitySubject.getPrincipal();
        assertEquals(NamedPrincipal.UNAUTHENTICATED, principal);
    }

    @Test
    public void testGetPrincipalWhenThreadContextHasNoUser() {
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, null);
        Principal principal = securitySubject.getPrincipal();
        assertEquals(NamedPrincipal.UNAUTHENTICATED, principal);
    }

    @Test
    public void testGetPrincipalWhenThreadContextHasUser() {

        AuthCredentials authCredentials = new AuthCredentials("testUser", "testPassword".getBytes(StandardCharsets.UTF_8));
        authCredentials.addAttribute("customAttribute", "value");
        User user = new User("testUser", Arrays.asList("role1", "role2"), authCredentials);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        Principal principal = securitySubject.getPrincipal();
        assertEquals(new NamedPrincipal("testUser"), principal);
    }

    @Test
    public void testAuthenticate() {
        // TODO: Implement test for the authenticate method if needed.
    }
}
