package com.amazon.opendistroforelasticsearch.security.authtoken;

import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateRequest.UpdateType;
import com.amazon.opendistroforelasticsearch.security.authtoken.config.AuthTokenServiceConfig;
import com.amazon.opendistroforelasticsearch.security.authtoken.client.PrivilegedConfigClient;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenRequest;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenResponse;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateAction;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.update.PushAuthTokenUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.authtoken.parser.ValidatingJsonParser;
import com.amazon.opendistroforelasticsearch.security.authtoken.validation.*;
import com.amazon.opendistroforelasticsearch.security.configuration.ProtectedConfigIndexService;
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
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class AuthTokenService { //implements SpecialPrivilegesEvaluationContextProvider {
    private static final Logger log = LogManager.getLogger(AuthTokenService.class);

    public static final Setting<String> INDEX_NAME = Setting.simpleString("opendistro.security.authtokens.index.name", ".opendistro_security_authtokens",
            Property.NodeScope);
    public static final Setting<TimeValue> CLEANUP_INTERVAL = Setting.timeSetting("opendistro.security.authtokens.cleanup_interval",
            TimeValue.timeValueHours(1), TimeValue.timeValueSeconds(1), Property.NodeScope, Property.Filtered);

    public static final String USER_TYPE = "opendistro_security_auth_token";
    public static final String USER_TYPE_FULL_CURRENT_PERMISSIONS = "opendistro_security_auth_token_full_current_permissions";

    private final String indexName;
    private final PrivilegedConfigClient privilegedConfigClient;
    //private final ConfigHistoryService configHistoryService;
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
    //private IndexCleanupAgent indexCleanupAgent;
    private long maxTokensPerUser = 100;

    public AuthTokenService() {
        indexName = "";
        privilegedConfigClient = null;
    }

    public AuthTokenService(
                            //ConfigHistoryService configHistoryService,
                            Client client,
                            Settings settings,
                            ThreadPool threadPool,
                            //ClusterService clusterService,
                            ProtectedConfigIndexService protectedConfigIndexService,
                            AuthTokenServiceConfig config) {
        this.indexName = INDEX_NAME.get(settings);
        //this.configHistoryService = configHistoryService;


        log.info("Palash printing index name " + indexName);
        this.setConfig(config);



        privilegedConfigClient = new PrivilegedConfigClient(client);



        protectedConfigIndexService.createIndex(new ProtectedConfigIndexService.ConfigIndex(indexName).mapping(AuthToken.INDEX_MAPPING)
                //.dependsOnIndices(configHistoryService.getIndexName())
                .onIndexReady(this::init)
        );

        //this.indexCleanupAgent = new IndexCleanupAgent(indexName, "expires_at", CLEANUP_INTERVAL.get(settings), privilegedConfigClient,
        //         clusterService, threadPool);
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


    /*public void getTokenByIdWithConfigSnapshot(String id, Consumer<AuthToken> onResult, Consumer<NoSuchAuthTokenException> onNoSuchAuthToken,
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
    }*/

    public AuthToken createToken(User user, CreateAuthTokenRequest request) throws TokenCreationException {
        if (config == null || !config.isEnabled()) {
            throw new TokenCreationException("Auth token handling is not enabled", RestStatus.INTERNAL_SERVER_ERROR);
        }

        if (log.isDebugEnabled()) {
            log.debug("create(user: " + user + ", request: " + request + ")");
        }

        Set<String> baseBackendRoles = user.getRoles();
        Set<String> baseOpendistroSecurityRoles = user.getOpenDistroSecurityRoles();

        String id = getRandomId();

        if (maxTokensPerUser == 0) {
            throw new TokenCreationException("Cannot create token. max_tokens_per_user is set to 0", RestStatus.FORBIDDEN);
        } else if (maxTokensPerUser > 0) {
            long existingTokenCount = countAuthTokensOfUser(user);

            log.info("Current Token count " + existingTokenCount);

            if (existingTokenCount + 1 > maxTokensPerUser) {
                throw new TokenCreationException(
                        "Cannot create token. Token limit per user exceeded. Max number of allowed tokens is " + maxTokensPerUser,
                        RestStatus.FORBIDDEN);
            }
        }

        OffsetDateTime now = OffsetDateTime.now().withNano(0);
        OffsetDateTime expiresAt = getExpiryTime(now, request);

        AuthToken authToken = new AuthToken(id, user.getName(), request.getTokenName(),
                now.toInstant(), expiresAt != null ? expiresAt.toInstant() : null, null);

        try {
            updateAuthToken(authToken, UpdateType.NEW);
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
        //jwtClaims.setProperty("requested", ObjectTreeXContent.toObjectTree(authToken.getRequestedPrivileges()));
        //jwtClaims.setProperty("base", ObjectTreeXContent.toObjectTree(authToken.getBase(), AuthTokenPrivilegeBase.COMPACT));


        String encodedJwt;

        try {
            encodedJwt = this.jwtProducer.processJwt(jwt);
        } catch (Exception e) {
            log.error("Error while creating JWT. Possibly the key configuration is not valid.", e);
            throw new TokenCreationException("Error while creating JWT. Possibly the key configuration is not valid.",
                    RestStatus.INTERNAL_SERVER_ERROR, e);
        }

        log.info("encodedJwt " + encodedJwt);
        log.info("authToken" + authToken.getId());
        return new CreateAuthTokenResponse(authToken, encodedJwt);

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

    public void setConfig(AuthTokenServiceConfig config) {
        if (config == null) {
            // Expected when Opendistro is not initialized yet
            log.info("Palash in setconfig null");
            return;
        }

        log.info("Palash in setconfig not null");
        this.config = config;
        this.jwtAudience = config.getJwtAud();
        this.maxTokensPerUser = config.getMaxTokensPerUser();

        log.info(this.jwtAudience + " == " + this.maxTokensPerUser + " == " + config.getJwtSigningKey() + " == " +  config.getJwtEncryptionKey());

        setKeys(config.getJwtSigningKey(), config.getJwtEncryptionKey());
    }

    private void init(ProtectedConfigIndexService.FailureListener failureListener) {
        log.info("Palash here in init");
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

    private long countAuthTokensOfUser(User user) {
        SearchRequest searchRequest = new SearchRequest(getIndexName())
                .source(new SearchSourceBuilder()
                .query(QueryBuilders.termQuery("user_name", user.getName()))
                .size(0));

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

            log.info("Palash in initJwtProducer 2");
            if (signingKey != null) {
                log.info("Palash in initJwtProducer 3");
                this.jwtProducer.setSignatureProvider(JwsUtils.getSignatureProvider(signingKey));
                this.jwsSignatureVerifier = JwsUtils.getSignatureVerifier(signingKey);
            } else {
                log.info("Palash in initJwtProducer 4");
                this.jwsSignatureVerifier = null;
            }

            if (this.encryptionKey != null) {
                log.info("Palash in initJwtProducer 5");
                this.jwtProducer.setEncryptionProvider(JweUtils.createJweEncryptionProvider(encryptionKey, ContentAlgorithm.A256CBC_HS512));
                this.jwtProducer.setJweRequired(true);
                this.jweDecryptionProvider = JweUtils.createJweDecryptionProvider(encryptionKey, ContentAlgorithm.A256CBC_HS512);
            } else {
                log.info("Palash in initJwtProducer 6");
                this.jweDecryptionProvider = null;
            }

        } catch (Exception e) {
            log.info("Palash in initJwtProducer 7");
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
            log.info("Printing signingKey " + signingKey);
            log.info("Printing encryptionKey " + encryptionKey);
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

    /*private Set<String> restrictRoles(CreateAuthTokenRequest request, Set<String> roles) {
        if (request.getRequestedPrivileges().getRoles() != null) {
            return Sets.intersection(new HashSet<>(request.getRequestedPrivileges().getRoles()), roles);
        } else {
            return roles;
        }
    }*/

    /*@Override
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


    }*/

    public void shutdown() {
        //this.indexCleanupAgent.shutdown();
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



    private String updateAuthToken(AuthToken authToken, UpdateType updateType) throws TokenUpdateException {
        AuthToken oldToken = null;

        try {
            oldToken = getTokenById(authToken.getId());
        } catch (NoSuchAuthTokenException e) {
            oldToken = null;
        }

        if (updateType == UpdateType.NEW && oldToken != null) {
            throw new TokenUpdateException("Token ID already exists: " + authToken.getId());
        }

        try (XContentBuilder xContentBuilder = XContentFactory.jsonBuilder()) {
            authToken.toXContent(xContentBuilder, ToXContent.EMPTY_PARAMS);

            IndexResponse indexResponse = privilegedConfigClient
                            .index(new IndexRequest(indexName)
                            .id(authToken.getId())
                            .source(xContentBuilder)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
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


        // Palash - Need to check what is this
        // Probably in case if it is not saved in Index, it is kept in memory 
        if (!sendTokenUpdates) {
            return "Update disabled";
        }

        try {
            PushAuthTokenUpdateResponse pushAuthTokenUpdateResponse = privilegedConfigClient
                    .execute(PushAuthTokenUpdateAction.INSTANCE, new PushAuthTokenUpdateRequest(authToken, updateType, 0))
                    .actionGet();

            if (log.isDebugEnabled()) {
                log.debug("Token update pushed: " + pushAuthTokenUpdateResponse);
            }

            log.info("Token update pushed: " + pushAuthTokenUpdateResponse);

            if (pushAuthTokenUpdateResponse.hasFailures()) {
                log.info("Token update failed: " + pushAuthTokenUpdateResponse.failures());
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




}
