package com.amazon.dlic.auth.http.jwt.authtoken.api.authtokenmodule;

import org.elasticsearch.action.ActionType;

public class GetAuthTokenAction extends ActionType<GetAuthTokenResponse> {

    public static final GetAuthTokenAction INSTANCE = new GetAuthTokenAction();
    public static final String NAME = "cluster:admin:searchguard:authtoken/_own/get";
    public static final String NAME_ALL = NAME.replace("/_own/", "/_all/");

    protected GetAuthTokenAction() {
        super(NAME, in -> new GetAuthTokenResponse(in));
    }
}

