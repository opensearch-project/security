package org.opensearch.security.user;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

/**
 * This interface will be defined in core following these changes. For now this is used for testing in the Security Plugin.
 *
 */
public interface InternalUserProvider {

    public void putInternalUser(String userInfo) throws java.io.IOException;

    public SecurityDynamicConfiguration<?> getInternalUser(String userInfo);

    public void removeInternalUser(String userInfo);

    public String getInternalUserAuthToken(String userInfo) throws IOException;
}
