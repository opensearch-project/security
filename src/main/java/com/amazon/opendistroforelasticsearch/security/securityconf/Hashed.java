package com.amazon.opendistroforelasticsearch.security.securityconf;

public interface Hashed {
    
    public String getHash();
    public void clearHash();

}
