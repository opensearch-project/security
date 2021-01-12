package com.amazon.opendistroforelasticsearch.security.authtoken.modules.update;

import org.elasticsearch.action.ActionType;

public class PushAuthTokenUpdateAction extends ActionType<PushAuthTokenUpdateResponse> {

    public static final PushAuthTokenUpdateAction INSTANCE = new PushAuthTokenUpdateAction();
    public static final String NAME = "cluster:admin/opendistro_security/auth_token/update/push";

    protected PushAuthTokenUpdateAction() {
        super(NAME, PushAuthTokenUpdateResponse::new);
    }
}

