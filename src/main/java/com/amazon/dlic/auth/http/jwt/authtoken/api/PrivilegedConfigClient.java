package com.amazon.dlic.auth.http.jwt.authtoken.api;

import com.amazon.dlic.auth.http.jwt.authtoken.api.client.ContextHeaderDecoratorClient;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.client.Client;

public class PrivilegedConfigClient extends ContextHeaderDecoratorClient {
    public static final String TOKEN_HEADER = ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX + "internal_auth_token";
    public static final String AUDIENCE_HEADER = ConfigConstants.OPENDISTRO_SECURITY_CONFIG_PREFIX + "internal_auth_token_audience";



    public PrivilegedConfigClient(Client in) {
        super(in, ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true", TOKEN_HEADER, null,
                AUDIENCE_HEADER, null);
    }

    public static PrivilegedConfigClient adapt(Client client) {
        if (client instanceof PrivilegedConfigClient) {
            return (PrivilegedConfigClient) client;
        } else {
            return new PrivilegedConfigClient(client);
        }
    }
}

