package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import java.util.Collections;
import java.util.List;

public abstract class RoleMappings {
    protected List<String> hosts= Collections.emptyList();
    protected java.util.List<String> users= Collections.emptyList();

    public abstract List<String> getUsers();
    public abstract List<String> getHosts();
}
