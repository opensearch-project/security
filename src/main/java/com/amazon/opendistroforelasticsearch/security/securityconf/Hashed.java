package com.amazon.opendistroforelasticsearch.security.securityconf;

public interface Hashed {

    String getHash();
    void setHash(String hash);
    void clearHash();
}
