package org.opensearch.security.identity;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import joptsimple.internal.Strings;
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
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;

public class SecurityTokenManager implements TokenManager {

    public static Settings DEMO_SETTINGS = Settings.builder()
        .put(
            "signing_key",
            Base64.getEncoder()
                .encodeToString(
                    "This is my super secret that no one in the universe will ever be able to guess in a bajillion years".getBytes(
                        StandardCharsets.UTF_8
                    )
                )
        )
        .put("encryption_key", Base64.getEncoder().encodeToString("encryptionKey".getBytes(StandardCharsets.UTF_8)))
        .build();

    ConfigModel configModel;
    private ClusterService cs;
    private ThreadPool threadPool;
    private UserService userService;

    public SecurityTokenManager(ClusterService cs, ThreadPool threadPool, UserService userService) {
        this.cs = cs;
        this.threadPool = threadPool;
        this.userService = userService;
    }

    JwtVendor jwtVendor = new JwtVendor(DEMO_SETTINGS, Optional.empty());

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
                return jwtVendor.createJwt(
                    cs.getClusterName().value(),
                    u.getName(),
                    claims.getAudience(),
                    300,
                    mappedRoles,
                    u.getRoles(),
                    false
                );
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).map(BearerAuthToken::new).orElseThrow(() -> new OpenSearchSecurityException("JWT creation failed."));
    }

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
}
