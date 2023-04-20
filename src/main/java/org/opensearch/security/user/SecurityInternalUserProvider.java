package org.opensearch.security.user;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import org.opensearch.common.inject.Inject;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

public class SecurityInternalUserProvider implements InternalUserProvider{

    UserService userService;

    @Inject
    public SecurityInternalUserProvider(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void putInternalUser(String userInfo) throws IOException {

        JsonNode content = null;
        content = DefaultObjectMapper.readTree(userInfo);
        final ObjectNode contentAsNode = (ObjectNode) content;

        SecurityDynamicConfiguration<?> internalUsersConfiguration = userService.load(userService.getUserConfigName(), true);
        internalUsersConfiguration = userService.createOrUpdateAccount((ObjectNode) content);
        userService.saveAndUpdateConfigs(userService.getUserConfigName().toString(), userService.client, CType.INTERNALUSERS, internalUsersConfiguration);
    }

    @Override
    public SecurityDynamicConfiguration<?> getInternalUser(String username) {

        final SecurityDynamicConfiguration<?> internalUsersConfiguration = userService.load(userService.getUserConfigName(), true);

        // no specific resource requested, return complete config
        if (username == null || username.length() == 0) {
            return internalUsersConfiguration;
        }

        final boolean userExisted = internalUsersConfiguration.exists(username);

        if (!userExisted) {
            throw new UserServiceException("Failed to retrieve requested internal user.");
        }

        internalUsersConfiguration.removeOthers(username);
        return internalUsersConfiguration;
    }

    @Override
    public void removeInternalUser(String username) {
        final SecurityDynamicConfiguration<?> internalUsersConfiguration = userService.load(userService.getUserConfigName(), true);
        internalUsersConfiguration.remove(username);
    }

    @Override
    public String getInternalUserAuthToken(String username) throws IOException {
        return userService.generateAuthToken(username);
    }

}
