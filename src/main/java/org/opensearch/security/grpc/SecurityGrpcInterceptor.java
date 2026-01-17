/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.grpc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;

import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;

/**
 * gRPC ServerInterceptor that extracts authentication credentials from gRPC metadata
 * and stores them in the OpenSearch ThreadContext for use by the security filter.
 * <p>
 * This interceptor supports:
 * <ul>
 *   <li>Basic Authentication via the "authorization" metadata key</li>
 *   <li>Bearer Token Authentication via the "authorization" metadata key</li>
 * </ul>
 */
public class SecurityGrpcInterceptor implements ServerInterceptor {

    private static final Logger log = LogManager.getLogger(SecurityGrpcInterceptor.class);

    /**
     * Standard gRPC metadata key for authorization header
     */
    public static final Metadata.Key<String> AUTHORIZATION_METADATA_KEY = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    /**
     * Metadata key for security tenant
     */
    public static final Metadata.Key<String> SECURITY_TENANT_METADATA_KEY = Metadata.Key.of(
        "securitytenant",
        Metadata.ASCII_STRING_MARSHALLER
    );

    /**
     * Metadata key for user impersonation
     */
    public static final Metadata.Key<String> IMPERSONATE_AS_METADATA_KEY = Metadata.Key.of(
        "opendistro_security_impersonate_as",
        Metadata.ASCII_STRING_MARSHALLER
    );

    /**
     * gRPC Context key for storing auth credentials
     */
    public static final Context.Key<AuthCredentials> GRPC_CREDENTIALS_CONTEXT_KEY = Context.key("security-credentials");

    private final ThreadContext threadContext;

    /**
     * Creates a new SecurityGrpcInterceptor.
     *
     * @param threadContext The OpenSearch ThreadContext for storing authentication info
     */
    public SecurityGrpcInterceptor(ThreadContext threadContext) {
        this.threadContext = threadContext;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
        ServerCall<ReqT, RespT> call,
        Metadata headers,
        ServerCallHandler<ReqT, RespT> next
    ) {
        log.trace("Intercepting gRPC call: {}", call.getMethodDescriptor().getFullMethodName());

        try {
            // Extract credentials from metadata
            AuthCredentials credentials = extractCredentials(headers);


            if (credentials != null) {

                // Store credentials info in ThreadContext for downstream security processing
                storeInThreadContext(credentials, headers);

                log.debug("Extracted credentials for user: {} from gRPC metadata", credentials.getUsername());
            } else {
                log.trace("No credentials found in gRPC metadata for call: {}", call.getMethodDescriptor().getFullMethodName());
            }

            // Extract and store tenant information if present
            String tenant = headers.get(SECURITY_TENANT_METADATA_KEY);
            if (tenant != null) {
                threadContext.putHeader("securitytenant", tenant);
                log.trace("Extracted security tenant: {} from gRPC metadata", tenant);
            }

            // Extract and store impersonation header if present
            String impersonateAs = headers.get(IMPERSONATE_AS_METADATA_KEY);
            if (impersonateAs != null) {
                threadContext.putHeader("opendistro_security_impersonate_as", impersonateAs);
                log.trace("Extracted impersonation target: {} from gRPC metadata", impersonateAs);
            }

            // Set the origin as GRPC for audit logging purposes
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, AuditLog.Origin.GRPC.toString());

            // Mark this as a gRPC channel type
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_CHANNEL_TYPE, "grpc");

            return Contexts.interceptCall(context, call, headers, next);

        } catch (Exception e) {
            log.error("Error during gRPC security interception", e);
            call.close(Status.INTERNAL.withDescription("Security processing error").withCause(e), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
    }

    /**
     * Extracts authentication credentials from gRPC metadata.
     * Supports Basic Authentication and Bearer Token authentication.
     *
     * @param headers The gRPC metadata headers
     * @return AuthCredentials if valid credentials found, null otherwise
     */
    private AuthCredentials extractCredentials(Metadata headers) {
        String authorizationHeader = headers.get(AUTHORIZATION_METADATA_KEY);

        if (authorizationHeader == null || authorizationHeader.isEmpty()) {
            return null;
        }

        String trimmedHeader = authorizationHeader.trim();

        // Basic Authentication
        if (trimmedHeader.toLowerCase().startsWith("basic ")) {
            return extractBasicCredentials(trimmedHeader);
        }

        // Bearer Token Authentication
        if (trimmedHeader.toLowerCase().startsWith("bearer ")) {
            return extractBearerCredentials(trimmedHeader);
        }

        log.debug("Unsupported authorization scheme in gRPC metadata: {}", trimmedHeader.split(" ")[0]);
        return null;
    }

    /**
     * Extracts Basic Auth credentials from the authorization header.
     *
     * @param authorizationHeader The authorization header value
     * @return AuthCredentials if valid, null otherwise
     */
    private AuthCredentials extractBasicCredentials(String authorizationHeader) {
        try {
            String base64Credentials = authorizationHeader.substring("Basic ".length()).trim();
            String decodedCredentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);

            // Format: username:password
            // username cannot contain ':', but password can
            int colonIndex = decodedCredentials.indexOf(':');

            if (colonIndex <= 0) {
                log.warn("Invalid Basic auth format in gRPC metadata");
                return null;
            }

            String username = decodedCredentials.substring(0, colonIndex);
            String password = decodedCredentials.length() > colonIndex + 1 ? decodedCredentials.substring(colonIndex + 1) : "";

            return new AuthCredentials(username, password.getBytes(StandardCharsets.UTF_8)).markComplete();

        } catch (IllegalArgumentException e) {
            log.warn("Failed to decode Basic auth credentials from gRPC metadata", e);
            return null;
        }
    }

    /**
     * Extracts Bearer token credentials from the authorization header.
     *
     * @param authorizationHeader The authorization header value
     * @return AuthCredentials with the token as native credentials
     */
    private AuthCredentials extractBearerCredentials(String authorizationHeader) {
        String token = authorizationHeader.substring("Bearer ".length()).trim();

        if (token.isEmpty()) {
            log.warn("Empty Bearer token in gRPC metadata");
            return null;
        }

        // For Bearer tokens, we create AuthCredentials with the token as native credentials
        // The actual token validation will be done by the authentication backend (e.g., JWT authenticator)
        // We use a placeholder username that will be replaced after token validation
        return new AuthCredentials("_grpc_bearer_token_user_", token).markComplete();
    }

    /**
     * Stores the extracted credentials information in the ThreadContext
     * for use by downstream security filters.
     *
     * @param credentials The extracted credentials
     * @param headers The original gRPC metadata headers
     */
    private void storeInThreadContext(AuthCredentials credentials, Metadata headers) {
        //TODO: update this to store the User for backends that need the raw header
        String authHeader = headers.get(AUTHORIZATION_METADATA_KEY);
        if (authHeader != null) {
            threadContext.putHeader("Authorization", authHeader);
        }
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, "grpc");
    }
}
