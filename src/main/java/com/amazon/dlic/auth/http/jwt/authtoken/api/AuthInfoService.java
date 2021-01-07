package com.amazon.dlic.auth.http.jwt.authtoken.api;

import com.amazon.opendistroforelasticsearch.security.privileges.SpecialPrivilegesEvaluationContext;
import com.amazon.opendistroforelasticsearch.security.privileges.SpecialPrivilegesEvaluationContextProviderRegistry;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.threadpool.ThreadPool;


public class AuthInfoService {
    private final ThreadPool threadPool;
    private final SpecialPrivilegesEvaluationContextProviderRegistry specialPrivilegesEvaluationContextProviderRegistry;

    public AuthInfoService(ThreadPool threadPool, SpecialPrivilegesEvaluationContextProviderRegistry specialPrivilegesEvaluationContextProviderRegistry) {
        this.threadPool = threadPool;
        this.specialPrivilegesEvaluationContextProviderRegistry = specialPrivilegesEvaluationContextProviderRegistry;
    }

    public User getCurrentUser() {
        User user = peekCurrentUser();

        if (user == null) {
            throw new ElasticsearchSecurityException("No user information available");
        }

        return user;
    }

    public User peekCurrentUser() {
        return threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
    }

    public SpecialPrivilegesEvaluationContext getSpecialPrivilegesEvaluationContext() {
        return specialPrivilegesEvaluationContextProviderRegistry.provide(getCurrentUser(), threadPool.getThreadContext());
    }

}

