package com.amazon.dlic.auth.http.jwt.authtoken.api;

import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule.*;
import com.amazon.dlic.auth.http.jwt.authtoken.api.config.ConfigHistoryService;
import com.amazon.dlic.auth.http.jwt.authtoken.api.config.ConfigSnapshot;
import com.amazon.dlic.auth.http.jwt.authtoken.api.exception.TokenUpdateException;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ConfigValidationException;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.ValidatingJsonParser;
import com.amazon.opendistroforelasticsearch.security.configuration.ProtectedConfigIndexService;
import com.amazon.opendistroforelasticsearch.security.privileges.SpecialPrivilegesEvaluationContext;
import com.amazon.opendistroforelasticsearch.security.privileges.SpecialPrivilegesEvaluationContextProvider;
import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.SecurityRoles;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.io.BaseEncoding;
import org.apache.cxf.rs.security.jose.jwa.ContentAlgorithm;
import org.apache.cxf.rs.security.jose.jwe.JweDecryptionOutput;
import org.apache.cxf.rs.security.jose.jwe.JweDecryptionProvider;
import org.apache.cxf.rs.security.jose.jwe.JweUtils;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsSignatureVerifier;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.IndexNotFoundException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.dlic.auth.http.jwt.authtoken.api.exception.InvalidTokenException;
import com.amazon.dlic.auth.http.jwt.authtoken.api.exception.NoSuchAuthTokenException;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.TokenCreationException;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class AuthTokenService implements SpecialPrivilegesEvaluationContextProvider {
    private static final Logger log = LogManager.getLogger(AuthTokenService.class);

    public static final Setting<String> INDEX_NAME = Setting.simpleString("opendistro.security.authtokens.index.name", ".opendistro_security_authtokens",
            Property.NodeScope);
    public static final Setting<TimeValue> CLEANUP_INTERVAL = Setting.timeSetting("opendistro.security.authtokens.cleanup_interval",
            TimeValue.timeValueHours(1), TimeValue.timeValueSeconds(1), Property.NodeScope, Property.Filtered);

    public static final String USER_TYPE = "opendistro_security_auth_token";
    public static final String USER_TYPE_FULL_CURRENT_PERMISSIONS = "opendistro_security_auth_token_full_current_permissions";

    private final String indexName;
    private final PrivilegedConfigClient privilegedConfigClient;
    private final ConfigHistoryService configHistoryService;
    private final Cache<String, AuthToken> idToAuthTokenMap = CacheBuilder.newBuilder().expireAfterWrite(60, TimeUnit.MINUTES).build();
    private JoseJwtProducer jwtProducer;
    private String jwtAudience;
    private JsonWebKey encryptionKey;
    private JsonWebKey signingKey;
    private JwsSignatureVerifier jwsSignatureVerifier;
    private JweDecryptionProvider jweDecryptionProvider;
    private AuthTokenServiceConfig config;
    private Set<AuthToken> unpushedTokens = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private boolean sendTokenUpdates = true;
    private boolean initialized = false;
    private IndexCleanupAgent indexCleanupAgent;
    private long maxTokensPerUser = 100;


    public AuthTokenService(PrivilegedConfigClient privilegedConfigClient, ConfigHistoryService configHistoryService, Settings settings,
                            ThreadPool threadPool, ClusterService clusterService, ProtectedConfigIndexService protectedConfigIndexService,
                            AuthTokenServiceConfig config) {
        this.indexName = INDEX_NAME.get(settings);
        this.privilegedConfigClient = privilegedConfigClient;
        this.configHistoryService = configHistoryService;

        this.setConfig(config);

        protectedConfigIndexService.createIndex(new ProtectedConfigIndexService.ConfigIndex(indexName).mapping(AuthToken.INDEX_MAPPING)
                .dependsOnIndices(configHistoryService.getIndexName()).onIndexReady(this::init));

        this.indexCleanupAgent = new IndexCleanupAgent(indexName, "expires_at", CLEANUP_INTERVAL.get(settings), privilegedConfigClient,
                clusterService, threadPool);
    }



    public AuthToken getTokenById(String id) throws NoSuchAuthTokenException {
        AuthToken result = idToAuthTokenMap.getIfPresent(id);

        if (result != null) {
            return result;
        } else {
            return getTokenByIdFromIndex(id);
        }

    }

    public void getTokenById(String id, Consumer<AuthToken> onResult, Consumer<NoSuchAuthTokenException> onNoSuchAuthToken,
                        Consumer<Exception> onFailure) {
        AuthToken result = idToAuthTokenMap.getIfPresent(id);

        if (result != null) {
            onResult.accept(result);
        } else {
            getTokenByIdFromIndex(id, onResult, onNoSuchAuthToken, onFailure);
        }

    }


    public AuthToken getTokenByIdFromIndex(String id) throws NoSuchAuthTokenException {
        CompletableFuture<AuthToken> completableFuture = new CompletableFuture<>();

        getTokenByIdFromIndex(id, completableFuture::complete, completableFuture::completeExceptionally, completableFuture::completeExceptionally);

        try {
            return completableFuture.get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof NoSuchAuthTokenException) {
                throw (NoSuchAuthTokenException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }

    }


    public void getTokenByIdFromIndex(String id, Consumer<AuthToken> onResult, Consumer<NoSuchAuthTokenException> onNoSuchAuthToken,
                                 Consumer<Exception> onFailure) {

        privilegedConfigClient.get(new GetRequest(indexName, id), new ActionListener<GetResponse>() {

            @Override
            public void onResponse(GetResponse getResponse) {
                if (getResponse.isExists()) {

                    try {
                        AuthToken authToken = AuthToken.parse(id, ValidatingJsonParser.readTree(getResponse.getSourceAsString()));

                        idToAuthTokenMap.put(id, authToken);

                        onResult.accept(authToken);
                    } catch (ConfigValidationException e) {
                        onFailure.accept(new RuntimeException("Token " + id + " is not stored in a valid format", e));
                    } catch (Exception e) {
                        log.error(e);
                        onFailure.accept(e);
                    }

                } else {
                    onNoSuchAuthToken.accept(new NoSuchAuthTokenException(id));
                }
            }

            @Override
            public void onFailure(Exception e) {
                if (e instanceof IndexNotFoundException) {
                    onNoSuchAuthToken.accept(new NoSuchAuthTokenException(id));
                } else {
                    onFailure.accept(e);
                }
            }
        });

    }


    public AuthToken getTokenByClaims(Map<String, Object> claims) throws NoSuchAuthTokenException, InvalidTokenException {
        CompletableFuture<AuthToken> completableFuture = new CompletableFuture<>();

        getTokenByClaims(claims, completableFuture::complete, completableFuture::completeExceptionally, completableFuture::completeExceptionally);

        try {
            return completableFuture.get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof NoSuchAuthTokenException) {
                throw (NoSuchAuthTokenException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    public void getTokenByClaims(Map<String, Object> claims, Consumer<AuthToken> onResult, Consumer<NoSuchAuthTokenException> onNoSuchAuthToken,
                            Consumer<Exception> onFailure) throws InvalidTokenException {
        String id = Objects.toString(claims.get(JwtConstants.CLAIM_JWT_ID), null);
        Set<String> audience = getClaimAsSet(claims, JwtConstants.CLAIM_AUDIENCE);

        if (!audience.contains(this.jwtAudience)) {
            throw new InvalidTokenException("Invalid JWT audience claim. Supplied: " + audience + "; Expected: " + this.jwtAudience);
        }

        if (id == null) {
            throw new InvalidTokenException("Supplied auth token does not have an id claim");
        }

        getTokenById(id, onResult, onNoSuchAuthToken, onFailure);

    }


    public void getTokenByIdWithConfigSnapshot(String id, Consumer<AuthToken> onResult, Consumer<NoSuchAuthTokenException> onNoSuchAuthToken,
                                          Consumer<Exception> onFailure) {
        getTokenById(id, (authToken) -> {
            if (authToken.getBase().getConfigVersions() == null || authToken.getBase().peekConfigSnapshot() != null) {
                onResult.accept(authToken);
            } else {
                configHistoryService.getConfigSnapshot(authToken.getBase().getConfigVersions(), (configSnapshot) -> {
                    authToken.getBase().setConfigSnapshot(configSnapshot);
                    onResult.accept(authToken);
                }, onFailure);
            }
        }, onNoSuchAuthToken, onFailure);
    }

    public AuthToken getByIdWithConfigSnapshot(String id) throws NoSuchAuthTokenException {
        CompletableFuture<AuthToken> completableFuture = new CompletableFuture<>();

        getTokenByIdWithConfigSnapshot(id, completableFuture::complete, completableFuture::completeExceptionally,
                completableFuture::completeExceptionally);

        try {
            return completableFuture.get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof NoSuchAuthTokenException) {
                throw (NoSuchAuthTokenException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    public AuthToken createToken(User user, CreateAuthTokenRequest request) throws TokenCreationException {
        if (config == null || !config.isEnabled()) {
            throw new TokenCreationException("Auth token handling is not enabled", RestStatus.INTERNAL_SERVER_ERROR);
        }

        if (log.isDebugEnabled()) {
            log.debug("create(user: " + user + ", request: " + request + ")");
        }

        Set<String> baseBackendRoles;
        Set<String> baseOpendistroSecurityRoles;
        Map<String, Object> baseAttributes;
        ConfigSnapshot configSnapshot;

        if (USER_TYPE.equals(user.getType())) {
            log.debug("User is based on an auth token. Resulting auth token will be based on the original one");

            String authTokenId = (String) user.getSpecialAuthzConfig();

            try {
                AuthToken existingAuthToken = getByIdWithConfigSnapshot(authTokenId);
                configSnapshot = existingAuthToken.getBase().getConfigSnapshot();
                baseBackendRoles = new HashSet<>(existingAuthToken.getBase().getBackendRoles());
                baseOpendistroSecurityRoles = new HashSet<>(existingAuthToken.getBase().getSearchGuardRoles());
                baseAttributes = existingAuthToken.getBase().getAttributes();
            } catch (NoSuchAuthTokenException e) {
                throw new TokenCreationException("Error while creating auth token: Could not find base token " + authTokenId,
                        RestStatus.INTERNAL_SERVER_ERROR, e);
            }

        } else {
            if ((request.isFreezePrivileges() && config.getFreezePrivileges() == AuthTokenServiceConfig.FreezePrivileges.USER_CHOOSES)
                    || config.getFreezePrivileges() == AuthTokenServiceConfig.FreezePrivileges.ALWAYS) {
                configSnapshot = configHistoryService.getCurrentConfigSnapshot(CType.ROLES, CType.ROLESMAPPING, CType.ACTIONGROUPS, CType.TENANTS);
            } else {
                configSnapshot = null;
            }

            baseBackendRoles = user.getRoles();
            baseOpendistroSecurityRoles = user.getOpenDistroSecurityRoles();
            baseAttributes = user.getStructuredAttributes();
        }

        String id = getRandomId();

        AuthTokenPrivilegeBase base = new AuthTokenPrivilegeBase(restrictRoles(request, baseBackendRoles),
                restrictRoles(request, baseOpendistroSecurityRoles),
                baseAttributes, configSnapshot != null ? configSnapshot.getConfigVersions() : null);


        if (log.isDebugEnabled()) {
            log.debug("base for auth token " + request + ": " + base);
        }

        base.setConfigSnapshot(configSnapshot);

        if (base.getBackendRoles().size() == 0 && base.getSearchGuardRoles().size() == 0) {
            throw new TokenCreationException(
                    "Cannot create token. The resulting token would have no privileges as the specified roles do not intersect with the user's roles. Specified: "
                            + request.getRequestedPrivileges().getRoles() + " User: " + baseBackendRoles + " + " + baseOpendistroSecurityRoles,
                    RestStatus.BAD_REQUEST);
        }

        if (maxTokensPerUser == 0) {
            throw new TokenCreationException("Cannot create token. max_tokens_per_user is set to 0", RestStatus.FORBIDDEN);
        } else if (maxTokensPerUser > 0) {
            long existingTokenCount = countAuthTokensOfUser(user);

            if (existingTokenCount + 1 > maxTokensPerUser) {
                throw new TokenCreationException(
                        "Cannot create token. Token limit per user exceeded. Max number of allowed tokens is " + maxTokensPerUser,
                        RestStatus.FORBIDDEN);
            }
        }


        OffsetDateTime now = OffsetDateTime.now().withNano(0);

        OffsetDateTime expiresAt = getExpiryTime(now, request);

        RequestedPrivileges requestedPrivilegesWithDefaultExclusions = request.getRequestedPrivileges()
                .excludeClusterPermissions(config.getExcludeClusterPermissions()).excludeIndexPermissions(config.getExcludeIndexPermissions());

        AuthToken authToken = new AuthToken(id, user.getName(), request.getTokenName(), requestedPrivilegesWithDefaultExclusions, base,
                now.toInstant(), expiresAt != null ? expiresAt.toInstant() : null, null);

        try {
            //updateAuthToken(authToken, UpdateType.NEW);
        } catch (Exception e) {
            throw new TokenCreationException("Error while creating token", RestStatus.INTERNAL_SERVER_ERROR, e);
        }

        return authToken;

    }


    public CreateAuthTokenResponse createJwt(User user, CreateAuthTokenRequest request) throws TokenCreationException {
        if (jwtProducer == null) {
            throw new TokenCreationException("AuthTokenProvider is not configured", RestStatus.INTERNAL_SERVER_ERROR);
        }

        AuthToken authToken = createToken(user, request);
        JwtClaims jwtClaims = new JwtClaims();
        JwtToken jwt = new JwtToken(jwtClaims);

        jwtClaims.setNotBefore(authToken.getCreationTime().getEpochSecond());

        if (authToken.getExpiryTime() != null) {
            jwtClaims.setExpiryTime(authToken.getExpiryTime().getEpochSecond());
        }

        jwtClaims.setSubject(user.getName());
        jwtClaims.setTokenId(authToken.getId());
        jwtClaims.setAudience(config.getJwtAud());
        jwtClaims.setProperty("requested", ObjectTreeXContent.toObjectTree(authToken.getRequestedPrivileges()));
        jwtClaims.setProperty("base", ObjectTreeXContent.toObjectTree(authToken.getBase(), AuthTokenPrivilegeBase.COMPACT));
        return null;
    }


    public JwtToken getVerifiedJwtToken(String encodedJwt) throws JwtException {
        if (this.jweDecryptionProvider != null) {
            JweDecryptionOutput decOutput = this.jweDecryptionProvider.decrypt(encodedJwt);
            encodedJwt = decOutput.getContentText();
        }

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        if (this.jwsSignatureVerifier != null) {
            boolean signatureValid = jwtConsumer.verifySignatureWith(jwsSignatureVerifier);

            if (!signatureValid) {
                throw new JwtException("Invalid JWT signature");
            }
        }

        validateClaims(jwt);

        return jwt;
    }


    public String revoke(User user, String id) throws NoSuchAuthTokenException, TokenUpdateException {
        if (log.isTraceEnabled()) {
            log.trace("revoke(" + user + ", " + id + ")");
        }

        AuthToken authToken = getTokenById(id);

        if (authToken.getRevokedAt() != null) {
            log.info("Auth token " + authToken + " was already revoked");
            return "Auth token was already revoked";
        }

        String updateStatus = updateAuthToken(authToken.getRevokedInstance(), PushAuthTokenUpdateRequest.UpdateType.REVOKED);

        if (updateStatus != null) {
            return updateStatus;
        }

        return "Auth token has been revoked";
    }

    public void setConfig(AuthTokenServiceConfig config) {
        if (config == null) {
            // Expected when Opendistro is not initialized yet
            return;
        }

        this.config = config;
        this.jwtAudience = config.getJwtAud();
        this.maxTokensPerUser = config.getMaxTokensPerUser();

        setKeys(config.getJwtSigningKey(), config.getJwtEncryptionKey());
    }

    private void init(ProtectedConfigIndexService.FailureListener failureListener) {
        initComplete();
    }

    private void validateClaims(JwtToken jwt) throws JwtException {
        JwtClaims claims = jwt.getClaims();

        if (claims == null) {
            throw new JwtException("The JWT does not have any claims");
        }

        JwtUtils.validateJwtExpiry(claims, 0, false);
        JwtUtils.validateJwtNotBefore(claims, 0, false);
        validateAudience(claims);
    }

    private void validateAudience(JwtClaims claims) throws JwtException {
        if (jwtAudience != null) {
            for (String audience : claims.getAudiences()) {
                if (jwtAudience.equals(audience)) {
                    return;
                }
            }
        }
        throw new JwtException("Invalid audience: " + claims.getAudiences() + "\nExpected audience: " + jwtAudience);
    }

    private synchronized void initComplete() {
        this.initialized = true;
        notifyAll();
    }

    public synchronized void waitForInitComplete(long timeoutMillis) {
        if (this.initialized) {
            return;
        }

        try {
            wait(timeoutMillis);
        } catch (InterruptedException e) {
        }

        if (!this.initialized) {
            throw new RuntimeException(this + " did not initialize after " + timeoutMillis);
        }
    }

    public String pushAuthTokenUpdate(PushAuthTokenUpdateRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("got auth token update: " + request);
        }

        AuthToken updatedAuthToken = request.getUpdatedToken();
        AuthToken existingAuthToken = this.idToAuthTokenMap.getIfPresent(updatedAuthToken.getId());

        if (existingAuthToken == null) {
            return "Auth token is not cached";
        } else {
            this.idToAuthTokenMap.put(updatedAuthToken.getId(), updatedAuthToken);
            return "Auth token updated";
        }
    }

    private String updateAuthToken(AuthToken authToken, PushAuthTokenUpdateRequest.UpdateType updateType) throws TokenUpdateException {
        AuthToken oldToken = null;

        try {
            oldToken = getTokenById(authToken.getId());
        } catch (NoSuchAuthTokenException e) {
            oldToken = null;
        }

        if (updateType == PushAuthTokenUpdateRequest.UpdateType.NEW && oldToken != null) {
            throw new TokenUpdateException("Token ID already exists: " + authToken.getId());
        }

        try (XContentBuilder xContentBuilder = XContentFactory.jsonBuilder()) {
            authToken.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);

            IndexResponse indexResponse = privilegedConfigClient
                    .index(new IndexRequest(indexName).id(authToken.getId()).source(xContentBuilder).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                    .actionGet();

            if (log.isDebugEnabled()) {
                log.debug("Token stored: " + indexResponse);
            }

        } catch (Exception e) {
            if (oldToken != null) {
                this.idToAuthTokenMap.put(oldToken.getId(), oldToken);
            } else {
                this.idToAuthTokenMap.invalidate(authToken.getId());
            }
            log.warn("Error while storing token " + authToken, e);
            throw new TokenUpdateException(e);
        }

        if (!sendTokenUpdates) {
            return "Update disabled";
        }


        try {
            PushAuthTokenUpdateResponse pushAuthTokenUpdateResponse = privilegedConfigClient
                    .execute(PushAuthTokenUpdateAction.INSTANCE, new PushAuthTokenUpdateRequest(authToken, updateType, 0)).actionGet();

            if (log.isDebugEnabled()) {
                log.debug("Token update pushed: " + pushAuthTokenUpdateResponse);
            }

            if (pushAuthTokenUpdateResponse.hasFailures()) {
                unpushedTokens.add(authToken);
                return "Update partially failed: " + pushAuthTokenUpdateResponse.failures();
            }

        } catch (Exception e) {
            log.warn("Token update push failed: " + authToken, e);
            // TODO
            unpushedTokens.add(authToken);
            return "Update partially failed: " + e;
        }
        return null;
    }

    private long countAuthTokensOfUser(User user) {
        SearchRequest searchRequest = new SearchRequest(getIndexName())
                .source(new SearchSourceBuilder().query(QueryBuilders.termQuery("user_name", user.getName())).size(0));

        SearchResponse searchResponse = privilegedConfigClient.search(searchRequest).actionGet();

        return searchResponse.getHits().getTotalHits().value;
    }

    private OffsetDateTime getExpiryTime(OffsetDateTime now, CreateAuthTokenRequest request) {
        OffsetDateTime expiresAfter = null;
        OffsetDateTime expiresAfterMax = null;

        if (request.getExpiresAfter() != null) {
            expiresAfter = now.plus(request.getExpiresAfter());
        }

        if (config.getMaxValidity() != null) {
            expiresAfterMax = now.plus(config.getMaxValidity());
        }

        if (expiresAfter == null) {
            expiresAfter = expiresAfterMax;
        } else if (expiresAfter != null && expiresAfterMax != null && expiresAfterMax.isBefore(expiresAfter)) {
            expiresAfter = expiresAfterMax;
        }

        return expiresAfter;
    }



    private String getRandomId() {
        UUID uuid = UUID.randomUUID();
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
        byteBuffer.putLong(uuid.getMostSignificantBits());
        byteBuffer.putLong(uuid.getLeastSignificantBits());

        return BaseEncoding.base64Url().encode(byteBuffer.array()).replace("=", "");
    }

    void initJwtProducer() {
        try {
            this.jwtProducer = new JoseJwtProducer();

            if (signingKey != null) {
                this.jwtProducer.setSignatureProvider(JwsUtils.getSignatureProvider(signingKey));
                this.jwsSignatureVerifier = JwsUtils.getSignatureVerifier(signingKey);
            } else {
                this.jwsSignatureVerifier = null;
            }

            if (this.encryptionKey != null) {
                this.jwtProducer.setEncryptionProvider(JweUtils.createJweEncryptionProvider(encryptionKey, ContentAlgorithm.A256CBC_HS512));
                this.jwtProducer.setJweRequired(true);
                this.jweDecryptionProvider = JweUtils.createJweDecryptionProvider(encryptionKey, ContentAlgorithm.A256CBC_HS512);
            } else {
                this.jweDecryptionProvider = null;
            }

        } catch (Exception e) {
            this.jwtProducer = null;
            log.error("Error while initializing JWT producer in AuthTokenProvider", e);
        }

    }

    public JsonWebKey getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(JsonWebKey signingKey) {
        if (Objects.equals(this.signingKey, signingKey)) {
            return;
        }

        log.info("Updating signing key for " + this);

        this.signingKey = signingKey;
        initJwtProducer();
    }


    public JsonWebKey getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(JsonWebKey encryptionKey) {
        if (Objects.equals(this.encryptionKey, encryptionKey)) {
            return;
        }

        log.info("Updating encryption key for " + this);

        this.encryptionKey = encryptionKey;
        initJwtProducer();
    }

    public void setKeys(JsonWebKey signingKey, JsonWebKey encryptionKey) {
        if (Objects.equals(this.signingKey, signingKey) && Objects.equals(this.encryptionKey, encryptionKey)) {
            return;
        }

        log.info("Updating keys for " + this);

        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
        initJwtProducer();
    }

    private Set<String> getClaimAsSet(Map<String, Object> claims, String claimName) {
        Object claim = claims.get(claimName);

        if (claim == null) {
            return Collections.emptySet();
        } else if (claim instanceof Collection) {
            return ((Collection<?>) claim).stream().map((e) -> String.valueOf(e)).collect(Collectors.toSet());
        } else {
            return Collections.singleton(String.valueOf(claim));
        }
    }

    private Set<String> restrictRoles(CreateAuthTokenRequest request, Set<String> roles) {
        if (request.getRequestedPrivileges().getRoles() != null) {
            return Sets.intersection(new HashSet<>(request.getRequestedPrivileges().getRoles()), roles);
        } else {
            return roles;
        }
    }

    @Override
    public void provide(User user, ThreadContext threadContext, Consumer<SpecialPrivilegesEvaluationContext> onResult,
                        Consumer<Exception> onFailure) {
        if (config == null || !config.isEnabled()) {
            onResult.accept(null);
            return;
        }

        if (user == null || !(USER_TYPE.equals(user.getType()))) {
            onResult.accept(null);
            return;
        }

        String authTokenId = (String) user.getSpecialAuthzConfig();

        if (log.isDebugEnabled()) {
            log.debug("AuthTokenService.provide(" + user.getName() + ") on " + authTokenId);
        }


        getTokenByIdWithConfigSnapshot(authTokenId, (authToken) -> {

            try {
                if (log.isTraceEnabled()) {
                    log.trace("Got token: " + authToken);
                }

                if (authToken.isRevoked()) {
                    log.info("Using revoked auth token: " + authToken);
                    onResult.accept(null);
                    return;
                }

                ConfigModel configModelSnapshot;

                if (authToken.getBase().getConfigSnapshot() == null) {
                    configModelSnapshot = configHistoryService.getCurrentConfigModel();
                } else {
                    if (authToken.getBase().getConfigSnapshot().hasMissingConfigVersions()) {
                        throw new RuntimeException("Stored config snapshot is not complete: " + authToken);
                    }

                    configModelSnapshot = configHistoryService.getConfigModelForSnapshot(authToken.getBase().getConfigSnapshot());
                }

                User userWithRoles = user.copy().backendRoles(authToken.getBase().getBackendRoles())
                        .openDistroSecurityRoles(authToken.getBase().getSearchGuardRoles()).build();

                TransportAddress callerTransportAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
                Set<String> mappedBaseRoles = configModelSnapshot.mapSecurityRoles(userWithRoles, callerTransportAddress);
                SecurityRoles filteredBaseSgRoles = configModelSnapshot.getSecurityRoles().filter(mappedBaseRoles);

                if (log.isDebugEnabled()) {
                    log.debug("AuthTokenService.provide returns SpecialPrivilegesEvaluationContext for " + user + "\nuserWithRoles: " + userWithRoles
                            + "\nmappedBaseRoles: " + mappedBaseRoles + "\nfilteredBaseSgRoles: " + filteredBaseSgRoles);
                }

                RestrictedSgRoles restrictedSgRoles = new RestrictedSgRoles(filteredBaseSgRoles, authToken.getRequestedPrivileges(),
                        configModelSnapshot.getActionGroupResolver());

                onResult.accept(new SpecialPrivilegesEvaluationContextImpl(userWithRoles, mappedBaseRoles, restrictedSgRoles,
                        authToken.getRequestedPrivileges()));
            } catch (Exception e) {
                log.error("Error in provide(" + user + "); authTokenId: " + authTokenId, e);
                onFailure.accept(e);
            }
        }, (noSuchAuthTokenException) -> {
            onFailure.accept(new ElasticsearchSecurityException("Cannot authenticate user due to invalid auth token " + authTokenId,
                    noSuchAuthTokenException));
        }, onFailure);


    }

    public void shutdown() {
        this.indexCleanupAgent.shutdown();
    }


    static class SpecialPrivilegesEvaluationContextImpl implements SpecialPrivilegesEvaluationContext {
        private final User user;
        private final Set<String> mappedRoles;
        private final SecurityRoles sgRoles;
        private final RequestedPrivileges requestedPrivileges;

        SpecialPrivilegesEvaluationContextImpl(User user, Set<String> mappedRoles, SecurityRoles sgRoles, RequestedPrivileges requestedPrivileges) {
            this.user = user;
            this.mappedRoles = mappedRoles;
            this.sgRoles = sgRoles;
            this.requestedPrivileges = requestedPrivileges;
        }

        @Override
        public User getUser() {
            return user;
        }

        @Override
        public Set<String> getMappedRoles() {
            return mappedRoles;
        }

        @Override
        public SecurityRoles getSgRoles() {
            return sgRoles;
        }

        @Override
        public boolean isSgConfigRestApiAllowed() {
            // This is kind of a hack in order to allow the creation of tokens which don't have the privilege to use the rest API
            return (requestedPrivileges.getClusterPermissions().contains("*")
                    || requestedPrivileges.getClusterPermissions().contains("cluster:admin:searchguard:configrestapi"))
                    && !requestedPrivileges.getExcludedClusterPermissions().contains("cluster:admin:searchguard:configrestapi");
        }

    }


    public String getIndexName() {
        return indexName;
    }

    boolean isSendTokenUpdates() {
        return sendTokenUpdates;
    }

    void setSendTokenUpdates(boolean sendTokenUpdates) {
        this.sendTokenUpdates = sendTokenUpdates;
    }
}
