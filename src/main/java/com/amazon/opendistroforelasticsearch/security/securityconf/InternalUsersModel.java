package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.List;
import java.util.Map;

public abstract class InternalUsersModel {
    
    public abstract boolean exists(String user);
    public abstract List<String> getBackenRoles(String user);
    public abstract Map<String, String> getAttributes(String user);
    public abstract String getDescription(String user);
    public abstract String getHash(String user);

}
