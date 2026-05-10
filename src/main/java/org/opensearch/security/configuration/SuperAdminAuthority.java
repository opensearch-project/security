package org.opensearch.security.configuration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;


public class SuperAdminAuthority {
    private static final Logger log = LogManager.getLogger(SuperAdminAuthority.class);

    private final AdminDNs adminDns;
    private final ThreadContext threadContext;
    private final String superadminSecret;

    public SuperAdminAuthority(final AdminDNs adminDns, final Settings settings, final ThreadPool threadPool) {
        this.adminDns = adminDns;
        this.threadContext = threadPool.getThreadContext();
        this.superadminSecret = SecuritySettings.SECURITY_SUPERADMIN_SECRET_SETTING.get(settings).toString();
    }

    public boolean isRequestFromSuperAdmin(final SecurityRequest request) {
        return isAdminViaDn(request) || isAdminViaSecret(request);
    }

    public AdminDNs getAdminDns() {
        return adminDns;
    }

    public boolean isAdminViaDn(final SecurityRequest request) {
        final String sslPrincipal = (String) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
        if(adminDns.isAdminDN(sslPrincipal)) {
            return true;
        }
        return false;
    }

    public boolean isAdminViaSecret(final SecurityRequest request) {
        return isSuperadminSecretValid(request.header(ConfigConstants.SECURITY_SUPERADMIN_SECRET_HEADER));
    }

    public boolean hasSecretHeader(final SecurityRequest request) {
        return !ObjectUtils.isEmpty(request.header(ConfigConstants.SECURITY_SUPERADMIN_SECRET_HEADER));
    }

    public boolean isSuperAdmin(final User user) {
        return user != null && (adminDns.isAdmin(user) || ConfigConstants.SECURITY_SUPERADMIN_SECRET_USER.equals(user.getName()));
    }

    public String getSuperadminSecretUserName() {
        return ConfigConstants.SECURITY_SUPERADMIN_SECRET_USER;
    }

    private boolean isSuperadminSecretValid(final String providedSecret) {
        if (ObjectUtils.isEmpty(superadminSecret) || ObjectUtils.isEmpty(providedSecret)) {
            return false;
        }

        try {
            return MessageDigest.isEqual(
                superadminSecret.getBytes(StandardCharsets.UTF_8),
                providedSecret.getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            log.debug("Error comparing superadmin secret", e);
            return false;
        }
    }
}
