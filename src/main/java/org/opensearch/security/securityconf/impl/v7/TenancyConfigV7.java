package org.opensearch.security.securityconf.impl.v7;

import com.fasterxml.jackson.annotation.JsonInclude;

public class TenancyConfigV7 {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public boolean multitenancy_enabled = true;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public boolean private_tenant_enabled = true;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String default_tenant = "";

}
