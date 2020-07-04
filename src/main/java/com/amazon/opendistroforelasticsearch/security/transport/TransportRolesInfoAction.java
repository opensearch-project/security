package com.amazon.opendistroforelasticsearch.security.transport;

import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.rolesinfo.RolesInfoAction;
import com.amazon.opendistroforelasticsearch.security.rolesinfo.RolesInfoRequest;
import com.amazon.opendistroforelasticsearch.security.rolesinfo.RolesInfoResponse;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.indices.IndicesService;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import java.util.Set;

public class TransportRolesInfoAction extends HandledTransportAction<ActionRequest, RolesInfoResponse> {

    private final Logger log = LogManager.getLogger(TransportRolesInfoAction.class);

    private static PrivilegesEvaluator evaluator = null;
    private static ThreadPool threadPool = null;

    @Inject
    public TransportRolesInfoAction(final TransportService transportService,
                                    final ActionFilters actionFilters,
                                    final IndicesService indicesService) {
        super(RolesInfoAction.NAME, transportService, actionFilters, RolesInfoRequest::new);
    }

    @Override
    protected void doExecute(Task task, ActionRequest request, ActionListener<RolesInfoResponse> actionListener) {

        final User user = (User)threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final TransportAddress remoteAddress = (TransportAddress) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        final Set<String> securityRoles = evaluator.mapRoles(user, remoteAddress);
        evaluator.mapRoles(user, remoteAddress);
        actionListener.onResponse(new RolesInfoResponse(user.getName(), securityRoles));
        //todo: handle error.
    }

    //fixme: any other better way?
    public static void setEvaluator(PrivilegesEvaluator eval, ThreadPool tp){
        evaluator = eval;
        threadPool = tp;
    }
}
