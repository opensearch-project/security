package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.util.concurrent.ThreadContext;

public class SpecialPrivilegesEvaluationContextProviderRegistry implements SpecialPrivilegesEvaluationContextProvider {
    private static final Logger log = LogManager.getLogger(SpecialPrivilegesEvaluationContextProviderRegistry.class);

    private List<SpecialPrivilegesEvaluationContextProvider> providers = new ArrayList<>();

    public void add(SpecialPrivilegesEvaluationContextProvider provider) {
        this.providers.add(provider);
    }

    @Override
    public void provide(User user, ThreadContext threadContext, Consumer<SpecialPrivilegesEvaluationContext> onResult,
                        Consumer<Exception> onFailure) {
        provide(this.providers.iterator(), user, threadContext, onResult, onFailure);
    }

    private void provide(Iterator<SpecialPrivilegesEvaluationContextProvider> iter, User user, ThreadContext threadContext,
                         Consumer<SpecialPrivilegesEvaluationContext> onResult, Consumer<Exception> onFailure) {
        try {
            if (iter.hasNext()) {
                SpecialPrivilegesEvaluationContextProvider provider = iter.next();

                provider.provide(user, threadContext, (result) -> {
                    if (result != null) {
                        onResult.accept(result);
                    } else {
                        provide(iter, user, threadContext, onResult, onFailure);
                    }
                }, onFailure);

            } else {
                onResult.accept(null);
            }
        } catch (Exception e) {
            log.error(e);
            onFailure.accept(e);
        }
    }

    public SpecialPrivilegesEvaluationContext provide(User user, ThreadContext threadContext) {
        CompletableFuture<SpecialPrivilegesEvaluationContext> completableFuture = new CompletableFuture<>();

        provide(user, threadContext, completableFuture::complete, completableFuture::completeExceptionally);

        try {
            return completableFuture.get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e.getCause());
        }
    }
}

