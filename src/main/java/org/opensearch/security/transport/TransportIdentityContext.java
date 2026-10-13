/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import java.net.InetSocketAddress;

import com.google.common.base.Strings;
import org.apache.commons.lang3.StringUtils;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserFactory;

final class TransportIdentityContext {

    private final User user;
    private final User authenticatedUser;
    private final String injectedUser;
    private final String injectedRoles;
    private final String origin;
    private final TransportAddress remoteAddress;

    private TransportIdentityContext(
        User user,
        User authenticatedUser,
        String injectedUser,
        String injectedRoles,
        String origin,
        TransportAddress remoteAddress
    ) {
        this.user = user;
        this.authenticatedUser = authenticatedUser;
        this.injectedUser = injectedUser;
        this.injectedRoles = injectedRoles;
        this.origin = origin;
        this.remoteAddress = remoteAddress;
    }

    static TransportIdentityContext capture(ThreadContext threadContext) {
        final Object remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        return new TransportIdentityContext(
            threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER),
            (User) threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER),
            threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER),
            threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES),
            threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN),
            remoteAddress instanceof TransportAddress transportAddress ? transportAddress : null
        );
    }

    void propagate(ThreadContext threadContext, boolean isSameNodeRequest) {
        propagateOrigin(threadContext);
        final boolean hasRemoteAddressHeader = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER) != null;
        final TransportAddress addressToPropagate = hasRemoteAddressHeader ? null : remoteAddress;
        if (isSameNodeRequest) {
            propagateTransientIdentity(threadContext, addressToPropagate);
        } else {
            propagateSerializedIdentity(threadContext, addressToPropagate);
        }
    }

    static boolean hasTransientIdentity(ThreadContext threadContext) {
        return threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER) != null
            || threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER) != null
            || threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES) != null
            || threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS) != null;
    }

    static void restoreOrigin(ThreadContext threadContext) {
        final String originHeader = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER);
        if (!Strings.isNullOrEmpty(originHeader)) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originHeader);
        }
    }

    static void restoreSerializedIdentity(
        ThreadContext threadContext,
        TransportAddress requestRemoteAddress,
        UserFactory userFactory,
        RemoteClusterIdentityPolicy remoteClusterIdentityPolicy
    ) {
        final String userHeader = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
        final String authenticatedUserHeader = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER_HEADER);
        final User user = deserializeUser(userHeader, threadContext, userFactory, remoteClusterIdentityPolicy);
        final User authenticatedUser = deserializeUser(authenticatedUserHeader, threadContext, userFactory, remoteClusterIdentityPolicy);

        restoreAuthenticatedUser(threadContext, user, authenticatedUser);
        restoreEffectiveIdentity(threadContext, userHeader, user);
        restoreRemoteAddress(threadContext, requestRemoteAddress);
        restoreRolesValidation(threadContext);
    }

    static void restoreRolesValidation(ThreadContext threadContext) {
        final String rolesValidation = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION_HEADER);
        if (!Strings.isNullOrEmpty(rolesValidation)) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION, rolesValidation);
        }
    }

    private void propagateOrigin(ThreadContext threadContext) {
        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER) != null) {
            return;
        }
        if (origin == null) {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, Origin.LOCAL.toString());
        } else if (!origin.isEmpty()) {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN_HEADER, origin);
        }
    }

    private void propagateTransientIdentity(ThreadContext threadContext, TransportAddress addressToPropagate) {
        if (addressToPropagate != null) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, addressToPropagate);
        }
        if (user != null) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        } else if (StringUtils.isNotEmpty(injectedRoles)) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRoles);
        } else if (StringUtils.isNotEmpty(injectedUser)) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, injectedUser);
        }
    }

    private void propagateSerializedIdentity(ThreadContext threadContext, TransportAddress addressToPropagate) {
        if (addressToPropagate != null) {
            threadContext.putHeader(
                ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER,
                Base64Helper.serializeObject(addressToPropagate.address())
            );
        }
        propagateAuthenticatedUser(threadContext);
        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER) == null) {
            if (user != null) {
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER, user.toSerializedBase64());
            } else if (StringUtils.isNotEmpty(injectedRoles)) {
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_HEADER, injectedRoles);
            } else if (StringUtils.isNotEmpty(injectedUser)) {
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_HEADER, injectedUser);
            }
        }
    }

    private void propagateAuthenticatedUser(ThreadContext threadContext) {
        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER_HEADER) != null || authenticatedUser == null) {
            return;
        }
        if (authenticatedUser.equals(user)) {
            if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_SAME_AS_SUBJECT_HEADER) == null) {
                threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_SAME_AS_SUBJECT_HEADER, Boolean.TRUE.toString());
            }
        } else {
            threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER_HEADER, authenticatedUser.toSerializedBase64());
        }
    }

    private static User deserializeUser(
        String header,
        ThreadContext threadContext,
        UserFactory userFactory,
        RemoteClusterIdentityPolicy remoteClusterIdentityPolicy
    ) {
        if (header == null) {
            return null;
        }
        return remoteClusterIdentityPolicy.sanitize(userFactory.fromSerializedBase64(header), threadContext);
    }

    private static void restoreAuthenticatedUser(ThreadContext threadContext, User user, User authenticatedUser) {
        if (threadContext.getPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER) != null) {
            return;
        }
        final boolean userIsAuthenticatedUser = Boolean.parseBoolean(
            threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_SAME_AS_SUBJECT_HEADER)
        );
        if (userIsAuthenticatedUser && user != null) {
            threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, user);
        } else if (authenticatedUser != null) {
            threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, authenticatedUser);
        }
    }

    private static void restoreEffectiveIdentity(ThreadContext threadContext, String userHeader, User user) {
        if (!Strings.isNullOrEmpty(userHeader)) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
            return;
        }
        final String injectedRoles = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_HEADER);
        final String injectedUser = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_HEADER);
        if (!Strings.isNullOrEmpty(injectedRoles)) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRoles);
        } else if (!Strings.isNullOrEmpty(injectedUser)) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, injectedUser);
        }
    }

    private static void restoreRemoteAddress(ThreadContext threadContext, TransportAddress requestRemoteAddress) {
        final String serializedAddress = threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER);
        final TransportAddress remoteAddress = Strings.isNullOrEmpty(serializedAddress)
            ? requestRemoteAddress
            : new TransportAddress((InetSocketAddress) Base64Helper.deserializeObject(serializedAddress));
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, remoteAddress);
    }
}
