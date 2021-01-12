package com.amazon.opendistroforelasticsearch.security.authtoken.api.transport;


import com.amazon.opendistroforelasticsearch.security.authtoken.AuthInfoService;
import com.amazon.opendistroforelasticsearch.security.authtoken.AuthTokenService;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenAction;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenRequest;
import com.amazon.opendistroforelasticsearch.security.authtoken.modules.create.CreateAuthTokenResponse;
import com.amazon.opendistroforelasticsearch.security.authtoken.validation.TokenCreationException;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

public class TransportCreateAuthTokenAction extends HandledTransportAction<CreateAuthTokenRequest, CreateAuthTokenResponse> {
    protected static Logger logger = LogManager.getLogger(TransportCreateAuthTokenAction.class);
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
