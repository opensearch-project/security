/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import org.greenrobot.eventbus.Subscribe;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.util.set.Sets;
import org.opensearch.identity.tokens.AuthToken;
import org.opensearch.identity.tokens.BasicAuthToken;
import org.opensearch.identity.tokens.TokenManager;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import java.util.*;

public class SecurityTokenManager implements TokenManager {

    Boolean extensionBwcCompatMode;
    User user;
    ConfigModel configModel;
    Set<String> mappedRoles;
    UserInjector userInjector;

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    public SecurityTokenManager(
            ThreadPool threadPool,
            final XFFResolver xffResolver,
            AuditLog auditLog,
            Settings settings
    ) {
        this.userInjector = new UserInjector(settings, threadPool, auditLog, xffResolver);
        this.extensionBwcCompatMode = settings.getAsBoolean(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE_DEFAULT);
        this.user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final TransportAddress caller = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        if (user == null) {
            user = userInjector.getInjectedUser();
        }
        this.mappedRoles = configModel.mapSecurityRoles(user, caller);
    }

    @Override
    public AuthToken issueToken(String audience) {
        if (extensionBwcCompatMode) {
            StringJoiner joiner = new StringJoiner("|");
            joiner.add(user.getName());
            joiner.add(String.join(",", user.getRoles()));
            joiner.add(String.join(",", Sets.union(user.getSecurityRoles(), mappedRoles)));

            return new BasicAuthToken(joiner.toString() + "This is the Token including the encrypted backend roles");
        } else {
            return new BasicAuthToken("This is standard Token without the roles");
        }
    }
}
