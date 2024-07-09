package com.amazon.dlic.auth.kerberos;

import com.amazon.dlic.auth.http.jwt.HTTPJwtAuthenticator;
import com.amazon.dlic.auth.http.kerberos.HTTPSpnegoAuthenticator;
import com.google.common.io.BaseEncoding;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.hc.core5.http.HttpHeaders;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class HTTPSpnegoAuthenticatorTest {

    @Test
    public void testNoKey() throws Exception {
        Settings settings = Settings.builder().build();

        HTTPSpnegoAuthenticator kerberosAuth = new HTTPSpnegoAuthenticator(settings, null);
        final AuthCredentials credentials = kerberosAuth.extractCredentials(
                (SecurityRequest) new FakeRestRequest() , null
        );

        Assert.assertNull(credentials);
    }

}
