package org.opensearch.security.auth;

import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtConstants;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.user.InternalUserTokenHandler;
import org.opensearch.security.user.UserService;
import org.opensearch.security.user.UserTokenHandler;
import org.opensearch.threadpool.ThreadPool;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

public class SecurityTokenManagerTests {

    final static String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
    final static String signingKey =
        "This is my super safe signing key that no one will ever be able to guess. It's would take billions of years and the world's most powerful quantum computer to crack";
    final static String signingKeyB64Encoded = BaseEncoding.base64().encode(signingKey.getBytes(StandardCharsets.UTF_8));

    SecurityTokenManager securityTokenManager;
    private UserTokenHandler userTokenhandler;
    private InternalUserTokenHandler internalUserTOkenHandler;
    private ClusterService clusterService;
    private Map<String, Object> claims;

    UserService userService;

    @Before
    public void setup() {
        claims = new HashMap<String, Object>() {
            {
                put(JwtConstants.CLAIM_AUDIENCE, "ext_0");
            }
        };
        MockitoAnnotations.openMocks(this);
        Settings settings = Settings.builder().put("signing_key", signingKeyB64Encoded).put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());
        Client client = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        ConfigurationRepository configurationRepository = mock(ConfigurationRepository.class);
        clusterService = mock(ClusterService.class);
        userService = mock(UserService.class);
        securityTokenManager = spy(
            new SecurityTokenManager(threadPool, clusterService, configurationRepository, client, settings, userService)
        );
        userTokenhandler = mock(UserTokenHandler.class);
        internalUserTOkenHandler = mock(InternalUserTokenHandler.class);
        securityTokenManager.setJwtVendor(jwtVendor);
        securityTokenManager.setInternalUserTokenHandler(internalUserTOkenHandler);
        securityTokenManager.setUserTokenHandler(userTokenhandler);
    }

    @Test
    public void testIssueOnBehalfOfTokenShouldPass() {
        AuthToken createdOnBehalfOfAuthToken = securityTokenManager.issueOnBehalfOfToken(claims);

        String encodedOBOTokenString = createdOnBehalfOfAuthToken.getTokenValue();
        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedOBOTokenString);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("obo", jwt.getClaim("typ"));
    }

    @Test
    public void testValidateOnBehalfOfTokenShouldPass() {
        AuthToken createdOnBehalfOfToken = securityTokenManager.issueOnBehalfOfToken(claims);
        doReturn(true).when(userTokenhandler).validateJustInTimeToken(createdOnBehalfOfToken);

        Assert.assertTrue(securityTokenManager.validateToken(createdOnBehalfOfToken));

    }
}
