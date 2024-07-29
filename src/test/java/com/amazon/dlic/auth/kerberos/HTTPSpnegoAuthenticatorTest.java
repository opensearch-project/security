package com.amazon.dlic.auth.kerberos;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import com.amazon.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator;

public class HTTPSpnegoAuthenticatorTest {

    @Test
    public void testNoKey() throws Exception {
        Settings settings = Settings.builder().build();

        HTTPSpnegoAuthenticator kerberosAuth = new HTTPSpnegoAuthenticator(settings, null);
        final AuthCredentials credentials = kerberosAuth.extractCredentials((SecurityRequest) new FakeRestRequest(), null);

        Assert.assertNull(credentials);
    }

}
