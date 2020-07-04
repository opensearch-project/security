package com.amazon.opendistroforelasticsearch.security.auth;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;

import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

final public class RoleInjector {
    protected final Logger log = LogManager.getLogger(RoleInjector.class);
    private Boolean injectRoleEnabled;
    private final String injectRoleStr;
    private ThreadContext threadContext = null;
    private final AuditLog auditLog;

    public RoleInjector(final Settings settings, final ThreadContext ctx, final AuditLog auditLog) {
        this.threadContext = ctx;
        this.auditLog = auditLog;
        this.injectRoleEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_INJECT_ROLE_ENABLED,
                false);
        this.injectRoleStr = ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECT_ROLE);

        if(log.isDebugEnabled()){
            log.debug("Injected role enabled: "+injectRoleEnabled());
            log.debug("Injected role: "+injectRoleStr);
        }
    }

    public boolean injectRoleEnabled() {
        return injectRoleEnabled && (injectRoleStr != null && !injectRoleStr.isEmpty());
    }

    public Set<String> getInjectedRoles() {
        if (!injectRoleEnabled())
            return null;

        //todo: any additional checks for user?
        // backend roles
        Set<String> newMappedRoles = new HashSet<>();
        if (!Strings.isNullOrEmpty(injectRoleStr)) {
            if (injectRoleStr.length() > 0) {
                newMappedRoles.addAll(Arrays.asList(injectRoleStr.split(",")));
            }
        }
        return newMappedRoles;
    }

    public User getUser(){
        User user = new User("pluginadmin");
        try {
            InetAddress iAdress = InetAddress.getByName("127.0.0.1");
            int port = 9300;
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, new TransportAddress(iAdress, port));
        } catch (UnknownHostException e) {
            log.error("Cannot parse remote IP or port:", e);
        }
        //todo: investigate
        //threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, AuditLog.Origin.TRANSPORT.toString());
        return user;
    }

}
