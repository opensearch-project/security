package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.securityconf.ConfigModel;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigModel;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.common.transport.TransportAddress;
import org.greenrobot.eventbus.Subscribe;

import java.util.Map;
import java.util.Set;

public abstract class AbstractPrivilegesEvaluator implements PrivilegesEvaluator {

    ConfigModel configModel;
    PrivilegesInterceptor privilegesInterceptor;
    DynamicConfigModel dcm;

    protected AbstractPrivilegesEvaluator(PrivilegesInterceptor privilegesInterceptor) {
        this.privilegesInterceptor = privilegesInterceptor;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
    }

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

    public Map<String, Boolean> mapTenants(final User user, Set<String> roles) {
        return this.configModel.mapTenants(user, roles);
    }

    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && dcm.isKibanaMultitenancyEnabled();
    }

    public String kibanaIndex() {
        return dcm.getKibanaIndexname();
    }

    public Set<String> getAllConfiguredTenantNames() {

        return configModel.getAllConfiguredTenantNames();
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && dcm.isDnfofEnabled();
    }

    public String kibanaOpendistroRole() {
        return dcm.getKibanaOpendistroRole();
    }

    public String kibanaServerUsername() {
        return dcm.getKibanaServerUsername();
    }
}
