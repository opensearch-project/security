package com.amazon.opendistroforelasticsearch.security.securityconf;

import java.util.List;
import java.util.Map;

public abstract class NodesDnModel {
    public abstract Map<String, List<String>> getNodesDn();
}
