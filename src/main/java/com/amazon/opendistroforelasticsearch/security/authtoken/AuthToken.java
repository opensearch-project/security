package com.amazon.opendistroforelasticsearch.security.authtoken;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Instant;

public class AuthToken {

    private static final Logger log = LogManager.getLogger(AuthToken.class);

    private static final long serialVersionUID = 6038589333544878668L;
    private String userName;
    private String tokenName;
    private String id;
    private Instant creationTime;
    private Instant expiryTime;
    private Instant revokedAt;

    AuthToken(){
    }

    public String getUserName() {
        return userName;
    }

    public String getTokenName() {
        return tokenName;
    }

    public String getId() {
        return id;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public Instant getExpiryTime() {
        return expiryTime;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }
}
