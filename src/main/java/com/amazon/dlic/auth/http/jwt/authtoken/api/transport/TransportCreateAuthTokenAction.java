package com.amazon.dlic.auth.http.jwt.authtoken.api.transport;

import com.amazon.dlic.auth.http.jwt.authtoken.api.AuthInfoService;
import com.amazon.dlic.auth.http.jwt.authtoken.api.AuthTokenService;
import com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule.CreateAuthTokenAction;
import com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule.CreateAuthTokenRequest;
import com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule.CreateAuthTokenResponse;
import com.amazon.dlic.auth.http.jwt.authtoken.api.validation.TokenCreationException;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

public class TransportCreateAuthTokenAction extends HandledTransportAction<CreateAuthTokenRequest, CreateAuthTokenResponse> {

    private final AuthTokenService authTokenService;
    private final AuthInfoService authInfoService;
    private final ThreadPool threadPool;

    @Inject
    public TransportCreateAuthTokenAction(TransportService transportService, ThreadPool threadPool, ActionFilters actionFilters,
                                          AuthTokenService authTokenService, AuthInfoService authInfoService) {
        super(CreateAuthTokenAction.NAME, transportService, actionFilters, CreateAuthTokenRequest::new);

        this.authTokenService = authTokenService;
        this.threadPool = threadPool;
        this.authInfoService = authInfoService;
    }

    @Override
    protected final void doExecute(Task task, CreateAuthTokenRequest request, ActionListener<CreateAuthTokenResponse> listener) {

        User user = authInfoService.getCurrentUser();

        threadPool.generic().submit(() -> {
            try {
                listener.onResponse(authTokenService.createJwt(user, request));
            } catch (TokenCreationException e) {
                listener.onFailure(new ElasticsearchStatusException(e.getMessage(), e.getRestStatus(), e));
            } catch (Exception e) {
                listener.onFailure(e);
            }
        });

    }
}

