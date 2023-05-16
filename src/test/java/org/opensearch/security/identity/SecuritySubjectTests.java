package org.opensearch.security.identity;

import org.junit.Test;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

import java.security.Principal;

import static org.junit.Assert.assertEquals;

public class SecuritySubjectTests {

    @Test
    public void testCurrentSubjectIsUnauthenticated() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        SecuritySubject subject = new SecuritySubject();
        subject.setThreadContext(threadContext);

        Principal principal = subject.getPrincipal();
        assertEquals(NamedPrincipal.UNAUTHENTICATED, principal);
    }

    @Test
    public void testCurrentSubjectIsPresent() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        SecuritySubject subject = new SecuritySubject();
        User user = new User("testuser");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        subject.setThreadContext(threadContext);

        Principal principal = subject.getPrincipal();
        assertEquals("testuser", principal.getName());
    }
}
