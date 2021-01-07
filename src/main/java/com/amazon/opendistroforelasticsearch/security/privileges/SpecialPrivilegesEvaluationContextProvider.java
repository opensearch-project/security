package com.amazon.opendistroforelasticsearch.security.privileges;

import java.util.function.Consumer;

import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.common.util.concurrent.ThreadContext;


@FunctionalInterface
public interface SpecialPrivilegesEvaluationContextProvider {
    void provide(User user, ThreadContext threadContext, Consumer<SpecialPrivilegesEvaluationContext> onResult, Consumer<Exception> onFailure);
}
