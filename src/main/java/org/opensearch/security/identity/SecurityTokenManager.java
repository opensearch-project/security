package org.opensearch.security.identity;

import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import joptsimple.internal.Strings;
import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JoseJwtProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.jose.jwt.JwtUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.identity.Subject;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.BearerAuthToken;
import org.opensearch.identity.tokens.OnBehalfOfClaims;
import org.opensearch.identity.tokens.TokenManager;
import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;
import static java.lang.Long.sum;
import static org.opensearch.security.util.AuthTokenUtils.isKeyNull;

/**
 * This class is the Security Plugin's implementation of the TokenManager used by all Identity Plugins.
 * It handles the issuance of both Service Account Tokens and On Behalf Of tokens.
 */
public class SecurityTokenManager implements TokenManager {

    private final Long MAX_EXPIRY_SECONDS = 600L;

    private static final Logger logger = LogManager.getLogger(SecurityTokenManager.class);
    private static JsonMapObjectReaderWriter jsonMapReaderWriter = new JsonMapObjectReaderWriter();

    ConfigModel configModel;
    private ClusterService cs;
    private ThreadPool threadPool;
    private UserService userService;
    private String claimsEncryptionKey;
    private JsonWebKey signingKey;
    private JoseJwtProducer jwtProducer;
    private LongSupplier timeProvider; // This should be in seconds
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    /**
     * The constructor for the SecurityTokenManager
     * @param cs The cluster service for the token manager to use
     * @param threadPool The thread pool for the token manager to use
     * @param userService The global instance of the user service that should be used
     * @param timeProvider An optional time provider that yields the current time in SECONDS
     * @param settings Any settings. It should always include those used for creating JWTs
     */
    public SecurityTokenManager(ClusterService cs, ThreadPool threadPool, UserService userService, final Optional<LongSupplier> timeProvider, final Settings settings) {
        this.cs = cs;
        this.threadPool = threadPool;
        this.userService = userService;
        setKeySettings(timeProvider, settings);
    }

    /**
     * This method allows for configuration of the time provider and settings values
     * This is primarily used for testing the ability of the token manager to properly handle different types of providers and settings
     * @param timeProvider An optional time provider. Any provided should be in SECONDS
     * @param settings Any settings to use for creating the JWTs
     */
    public void setKeySettings(final Optional<LongSupplier> timeProvider, final Settings settings) {
        JoseJwtProducer jwtProducer = new JoseJwtProducer();
        try {
            this.signingKey = createJwkFromSettings(settings);
        } catch (Exception e) {
            throw ExceptionUtils.createJwkCreationException(e);
        }
        this.jwtProducer = jwtProducer;
        if (isKeyNull(settings, "encryption_key")) {
            throw new IllegalArgumentException("encryption_key cannot be null");
        } else {
            this.claimsEncryptionKey = settings.get("encryption_key");
            this.encryptionDecryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        }
        if (timeProvider != null && timeProvider.isPresent()) {  // Check if timeProvider is not null and then if it's present
            this.timeProvider = timeProvider.get();
        } else {
            this.timeProvider = () -> System.currentTimeMillis() / 1000;
        }
    }

    /**
     * An overridden method which creates an OnBehalfOf token based on the provided subject and OnBehalfOf claims
     * @param subject The subject to be used as the issuer of the token
     * @param claims The claims to be used to fill the token fields
     * @return A new authToken in the form of a BearerAuthToken
     */
    @Override
    public AuthToken issueOnBehalfOfToken(Subject subject, OnBehalfOfClaims claims) {
        User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        Optional<User> userOptional = Optional.ofNullable(user);

        if (userOptional.isEmpty()) {
            throw new OpenSearchSecurityException("Cannot issue on behalf of token.");
        }

        if (Strings.isNullOrEmpty(claims.getAudience())) {
            throw new OpenSearchSecurityException("Cannot issue on behalf of token without an audience claim.");
        }

        final TransportAddress caller = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        Set<String> mappedRoles = mapRoles(user, caller);

        return userOptional.map(u -> {
            try {
                return createJwt(
                    cs.getClusterName().value(),
                    u.getName(),
                    claims.getAudience(),
                        claims.getExpiration(),
                    mappedRoles,
                    u.getRoles(),
                    false
                );
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).map(BearerAuthToken::new).orElseThrow(() -> new OpenSearchSecurityException("JWT creation failed."));
    }

    /**
     * An overridden method that creates a new ServiceAccountToken based on the provided extension ID
     * @param extensionUniqueId The id for the extension who should have a service account token created
     * @return A new AuthTokne in the form of a BasicAuthToken
     * @throws OpenSearchSecurityException Thrown if the internal user account for the extension cannot be found etc.
     */
    @Override
    public AuthToken issueServiceAccountToken(String extensionUniqueId) throws OpenSearchSecurityException {
        try {
            return new BasicAuthToken(this.userService.generateAuthToken(extensionUniqueId));
        } catch (Exception e) {
            throw new OpenSearchSecurityException(String.valueOf(e));
        }
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

    /*
     * The default configuration of this web key should be:
     *   KeyType: OCTET
     *   PublicKeyUse: SIGN
     *   Encryption Algorithm: HS512
     * */
    static JsonWebKey createJwkFromSettings(Settings settings) {
        if (!isKeyNull(settings, "signing_key")) {
            String signingKey = settings.get("signing_key");

            JsonWebKey jwk = new JsonWebKey();

            jwk.setKeyType(KeyType.OCTET);
            jwk.setAlgorithm("HS512");
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            jwk.setProperty("k", signingKey);

            return jwk;
        } else {
            Settings jwkSettings = settings.getAsSettings("jwt").getAsSettings("key");

            if (jwkSettings.isEmpty()) {
                throw new OpenSearchSecurityException(
                        "Settings for signing key is missing. Please specify at least the option signing_key with a shared secret."
                );
            }

            JsonWebKey jwk = new JsonWebKey();

            for (String key : jwkSettings.keySet()) {
                jwk.setProperty(key, jwkSettings.get(key));
            }

            return jwk;
        }
    }

    public String createJwt(
            String issuer,
            String subject,
            String audience,
            Long expirySeconds,
            Set<String> roles,
            Set<String> backendRoles,
            boolean roleSecurityMode
    ) {
        final long nowAsSecs = timeProvider.getAsLong();
        final long maxExpiryTime = sum(nowAsSecs, MAX_EXPIRY_SECONDS);
        final long expiryTime = sum(nowAsSecs, expirySeconds);
        jwtProducer.setSignatureProvider(JwsUtils.getSignatureProvider(signingKey));
        JwtClaims jwtClaims = new JwtClaims();
        JwtToken jwt = new JwtToken(jwtClaims);

        jwtClaims.setIssuer(issuer);

        jwtClaims.setIssuedAt(nowAsSecs);

        jwtClaims.setSubject(subject);

        jwtClaims.setAudience(audience);

        jwtClaims.setNotBefore(nowAsSecs);

        if (expirySeconds > MAX_EXPIRY_SECONDS) {
            throw new OpenSearchException("The provided expiration time exceeds the maximum allowed duration of " + MAX_EXPIRY_SECONDS + " seconds");
        }

        if (expirySeconds <= 0) {
            throw new OpenSearchException("The expiration time should be a positive integer");
        }

        jwtClaims.setExpiryTime(expiryTime);

        if (roles != null) {
            String listOfRoles = String.join(",", roles);
            jwtClaims.setProperty("er", encryptionDecryptionUtil.encrypt(listOfRoles));
        } else {
            throw new OpenSearchException("Roles cannot be null");
        }

        if (!roleSecurityMode && backendRoles != null) {
            String listOfBackendRoles = String.join(",", backendRoles);
            jwtClaims.setProperty("br", listOfBackendRoles);
        }

        String encodedJwt = jwtProducer.processJwt(jwt);

        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Created JWT: "
                            + encodedJwt
                            + "\n"
                            + jsonMapReaderWriter.toJson(jwt.getJwsHeaders())
                            + "\n"
                            + JwtUtils.claimsToJson(jwt.getClaims())
            );
        }

        return encodedJwt;
    }
}
