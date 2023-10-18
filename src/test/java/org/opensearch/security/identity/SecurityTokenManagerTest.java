package org.opensearch.security.identity;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.Subject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.identity.tokens.OnBehalfOfClaims;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensearch.security.identity.SecurityTokenManager.createJwkFromSettings;

public class SecurityTokenManagerTest {

    private SecurityTokenManager tokenManager;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private UserService userService;
    private ConfigModel configModel;
    private ThreadContext threadContext;
    private Appender mockAppender;
    private ArgumentCaptor<LogEvent> logEventCaptor;

    @Before
    public void setUp() {
        clusterService = mock(ClusterService.class);
        threadPool = mock(ThreadPool.class);
        threadContext = new ThreadContext(Settings.EMPTY);
        userService = mock(UserService.class);
        configModel = mock(ConfigModel.class);

        // Create a Settings instance for testing
        Settings settings = Settings.builder()
            .put(
                "signing_key",
                Base64.getEncoder()
                    .encodeToString(
                        "This is my super secret that no one in the universe will ever be able to guess in a bajillion years".getBytes()
                    )
            )
            .put("encryption_key", Base64.getEncoder().encodeToString("encryptionKey".getBytes()))
            .build();

        tokenManager = new SecurityTokenManager(clusterService, threadPool, userService, null, settings);
        tokenManager.configModel = configModel;
        ClusterName clusterName = new ClusterName("mockCluster");

        when(threadPool.getThreadContext()).thenReturn(threadContext);
        when(clusterService.getClusterName()).thenReturn(clusterName);
    }

    @Test
    public void testIssueOnBehalfOfTokenWithValidUser() {
        User user = new User("testUser", Arrays.asList("role1", "role2"), null);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        OnBehalfOfClaims claims = new OnBehalfOfClaims("audience", "subject");
        AuthToken authToken = tokenManager.issueOnBehalfOfToken(mock(Subject.class), claims);
        assertEquals(BearerAuthToken.class, authToken.getClass());
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testIssueOnBehalfOfTokenWithNullUser() {
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, null);
        OnBehalfOfClaims claims = new OnBehalfOfClaims("audience", "subject");
        tokenManager.issueOnBehalfOfToken(mock(Subject.class), claims);
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testIssueOnBehalfOfTokenWithEmptyAudience() {
        User user = new User("testUser", Arrays.asList("role1", "role2"), null);
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        OnBehalfOfClaims claims = new OnBehalfOfClaims("", "subject");
        tokenManager.issueOnBehalfOfToken(mock(Subject.class), claims);
    }

    @Test
    public void testIssueServiceAccountToken() throws IOException {
        String extensionUniqueId = "testExtension";
        when(userService.generateAuthToken(extensionUniqueId)).thenReturn("Basic dGVzdEV4dGVuc2lvbjp0ZXN0UGFzc3dvcmQ"); // testExtension:testPassword

        AuthToken authToken = tokenManager.issueServiceAccountToken(extensionUniqueId);
        BasicAuthToken basicAuthToken = (BasicAuthToken) authToken;

        assertEquals(BasicAuthToken.class, authToken.getClass());
        assertEquals("testExtension", basicAuthToken.getUser());
        assertEquals("testPassword", basicAuthToken.getPassword());
    }

    @Test(expected = OpenSearchSecurityException.class)
    public void testIssueServiceAccountTokenWithException() throws IOException {
        String extensionUniqueId = "12345";
        when(userService.generateAuthToken(extensionUniqueId)).thenThrow(new RuntimeException("Token generation failed"));
        tokenManager.issueServiceAccountToken(extensionUniqueId);
    }

    @Test
    public void testCreateJwkFromSettingsThrowsException() {
        Settings faultySettings = Settings.builder().put("key.someProperty", "badValue").build();

        Exception thrownException = assertThrows(Exception.class, () -> tokenManager.setKeySettings(null, faultySettings));

        String expectedMessagePart = "An error occurred during the creation of Jwk: ";
        assertTrue(thrownException.getMessage().contains(expectedMessagePart));
    }

    @Test
    public void testJsonWebKeyPropertiesSetFromJwkSettings() throws Exception {
        Settings settings = Settings.builder().put("jwt.key.key1", "value1").put("jwt.key.key2", "value2").build();

        JsonWebKey jwk = createJwkFromSettings(settings);

        assertEquals("value1", jwk.getProperty("key1"));
        assertEquals("value2", jwk.getProperty("key2"));
    }

    @Test
    public void testJsonWebKeyPropertiesSetFromSettings() {
        Settings jwkSettings = Settings.builder().put("key1", "value1").put("key2", "value2").build();

        JsonWebKey jwk = new JsonWebKey();
        for (String key : jwkSettings.keySet()) {
            jwk.setProperty(key, jwkSettings.get(key));
        }

        assertEquals("value1", jwk.getProperty("key1"));
        assertEquals("value2", jwk.getProperty("key2"));
    }

    @Test
    public void testCreateJwkFromSettings() throws Exception {
        Settings settings = Settings.builder().put("signing_key", "abc123").build();

        JsonWebKey jwk = createJwkFromSettings(settings);
        assertEquals("HS512", jwk.getAlgorithm());
        assertEquals("sig", jwk.getPublicKeyUse().toString());
        assertEquals("abc123", jwk.getProperty("k"));
    }

    @Test
    public void testCreateJwkFromSettingsWithoutSigningKey() {
        Settings settings = Settings.builder().put("jwt", "").build();
        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                createJwkFromSettings(settings);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals(
                "OpenSearchSecurityException[Settings for signing key is missing. Please specify at least the option signing_key with a shared secret.]",
                exception.getMessage()
        );
    }

    @Test
    public void testCreateJwtWithRoles() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        Set<String> roles = Set.of("IT", "HR");
        Set<String> backendRoles = Set.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        long expirySeconds = 300L;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        tokenManager.setKeySettings(Optional.of(currentTime), settings);
        String encodedJwt = tokenManager.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        assertEquals("cluster_0", jwt.getClaim("iss"));
        assertEquals("admin", jwt.getClaim("sub"));
        assertEquals("audience_0", jwt.getClaim("aud"));
        assertNotNull(jwt.getClaim("iat"));
        assertNotNull(jwt.getClaim("exp"));
        assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertEquals(Set.of(expectedRoles), Set.of(encryptionUtil.decrypt(jwt.getClaim("er").toString())));
        assertNull(jwt.getClaim("br"));
    }

    @Test
    public void testCreateJwtWithRoleSecurityMode() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        Set<String> roles = Set.of("IT", "HR");
        Set<String> backendRoles = Set.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        String expectedBackendRoles = "Sales,Support";

        long expirySeconds = 300L;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder()
                .put("signing_key", "abc123")
                .put("encryption_key", claimsEncryptionKey)
                // CS-SUPPRESS-SINGLE: RegexpSingleline get Extensions Settings
                .put(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, "true")
                // CS-ENFORCE-SINGLE
                .build();


        tokenManager.setKeySettings(Optional.of(currentTime), settings);
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        String encodedJwt = tokenManager.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        assertEquals("cluster_0", jwt.getClaim("iss"));
        assertEquals("admin", jwt.getClaim("sub"));
        assertEquals("audience_0", jwt.getClaim("aud"));
        assertNotNull(jwt.getClaim("iat"));
        assertNotNull(jwt.getClaim("exp"));
        assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        assertEquals(Set.of(expectedRoles), Set.of(encryptionUtil.decrypt(jwt.getClaim("er").toString())));
        assertNotNull(jwt.getClaim("br"));
        assertEquals(expectedBackendRoles, jwt.getClaim("br"));
    }

    @Test
    public void testCreateJwtWithNegativeExpiry() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        Set<String> roles = Set.of("admin");
        long expirySeconds = -300L;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();


        tokenManager.setKeySettings(null, settings);
        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                tokenManager.createJwt(issuer, subject, audience, expirySeconds, roles, Set.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("OpenSearchException[The expiration time should be a positive integer]", exception.getMessage());
    }

    @Test
    public void testCreateJwtWithExceededExpiry() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        Set<String> roles = Set.of("IT", "HR");
        Set<String> backendRoles = Set.of("Sales", "Support");
        long expirySeconds = 900L;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();


        tokenManager.setKeySettings(Optional.of(currentTime), settings);
        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                tokenManager.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals(
                "OpenSearchException[The provided expiration time exceeds the maximum allowed duration of 600 seconds]",
                exception.getMessage()
        );
    }

    @Test
    public void testCreateJwtWithBadEncryptionKey() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        Set<String> roles = Set.of("admin");
        long expirySeconds = 300L;

        Settings settings = Settings.builder().put("signing_key", "abc123").build();


        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                tokenManager.setKeySettings(null, settings);
                tokenManager.createJwt(issuer, subject, audience, expirySeconds, roles, Set.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("java.lang.IllegalArgumentException: encryption_key cannot be null", exception.getMessage());
    }

    @Test
    public void testCreateJwtWithBadRoles() {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        Set<String> roles = null;
        long expirySeconds = 300L;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        tokenManager.setKeySettings(null, settings);
        Throwable exception = assertThrows(RuntimeException.class, () -> {
            try {
                tokenManager.createJwt(issuer, subject, audience, expirySeconds, roles, Set.of(), true);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("OpenSearchException[Roles cannot be null]", exception.getMessage());
    }

    @Test
    public void testCreateJwtLogsCorrectly() throws Exception {
        mockAppender = mock(Appender.class);
        logEventCaptor = ArgumentCaptor.forClass(LogEvent.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        Logger logger = (Logger) LogManager.getLogger(SecurityTokenManager.class);
        logger.addAppender(mockAppender);
        logger.setLevel(Level.DEBUG);

        // Mock settings and other required dependencies
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();

        tokenManager.setKeySettings(Optional.of(currentTime), settings);
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        Set<String> roles = Set.of("IT", "HR");
        Set<String> backendRoles = Set.of("Sales", "Support");
        long expirySeconds = 300L;

        tokenManager.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        verify(mockAppender, times(1)).append(logEventCaptor.capture());

        LogEvent logEvent = logEventCaptor.getValue();
        String logMessage = logEvent.getMessage().getFormattedMessage();
        assertTrue(logMessage.startsWith("Created JWT:"));

        String[] parts = logMessage.split("\\.");
        assertTrue(parts.length >= 3);
    }
}
