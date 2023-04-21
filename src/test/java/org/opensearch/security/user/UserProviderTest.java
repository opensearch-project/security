package org.opensearch.security.user;

import java.io.File;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterHelper;

public class UserProviderTest extends SingleClusterTest {

    private static final String ENABLED_SERVICE_ACCOUNT_BODY  =  "{"
            + " \"username\": \"enabledService1\", "
            + " \"attributes\": { \"owner\": \"test_owner\", "
            + "\"isEnabled\": \"true\"}"
            + " }\n";

    private static final String DISABLED_SERVICE_ACCOUNT_BODY = "{"
            + " \"username\": \"disabledService1\", "
            + " \"attributes\": { \"owner\": \"test_owner\", "
            + "\"isEnabled\": \"false\"}"
            + " }\n";
    private static final String ENABLED_NOT_SERVICE_ACCOUNT_BODY = "{"
            + " \"username\": \"enabledNotService1\", "
            + " \"attributes\": { \"owner\": \"user_is_owner_1\", "
            + "\"isEnabled\": \"true\"}"
            + " }\n";
    private static final String PASSWORD_SERVICE = "{ \"password\" : \"test\","
            + " \"username\": \"passwordService1\", "
            + " \"attributes\": { \"owner\": \"test_owner\", "
            + "\"isEnabled\": \"true\"}"
            + " }\n";
    private static final String HASH_SERVICE = "{ \"owner\" : \"test_owner\","
            + " \"username\": \"hashService1\", "
            + " \"attributes\": { \"owner\": \"test_owner\", "
            + "\"isEnabled\": \"true\"}"
            + " }\n";
    private static final String PASSWORD_HASH_SERVICE = "{ \"password\" : \"test\", \"hash\" : \"123\","
            + " \"username\": \"passwordHashService1\", "
            + " \"attributes\": { \"owner\": \"test_owner\", "
            + "\"isEnabled\": \"true\"}"
            + " }\n";

    private UserService userService;

    private SecurityInternalUserProvider userProvider;

    @Test
    public void testAddConfigurationInfo() {

        try {
            userProvider.putInternalUser(ENABLED_SERVICE_ACCOUNT_BODY);
            userProvider.putInternalUser(DISABLED_SERVICE_ACCOUNT_BODY);
            userProvider.putInternalUser(ENABLED_NOT_SERVICE_ACCOUNT_BODY);
            userProvider.putInternalUser(PASSWORD_HASH_SERVICE);
            userProvider.putInternalUser(HASH_SERVICE);
            userProvider.putInternalUser(PASSWORD_HASH_SERVICE);
        } catch (java.io.IOException ex){
            throw new RuntimeException(ex);
        }
    }

    @Test
    public void testAddThenRetrieveConfigurationInfo() {

        try {
            userProvider.putInternalUser(ENABLED_SERVICE_ACCOUNT_BODY);
            userProvider.putInternalUser(DISABLED_SERVICE_ACCOUNT_BODY);
            userProvider.putInternalUser(ENABLED_NOT_SERVICE_ACCOUNT_BODY);
            userProvider.putInternalUser(PASSWORD_HASH_SERVICE);
            userProvider.putInternalUser(HASH_SERVICE);
            userProvider.putInternalUser(PASSWORD_HASH_SERVICE);
        } catch (java.io.IOException ex){
            throw new RuntimeException(ex);
        }

        SecurityDynamicConfiguration<?> response = userProvider.getInternalUser("enabledService1");
        assert(response.exists("enabledService1"));
        assert(response.getCEntries().size() == 1);

        response = userProvider.getInternalUser("disabledService1");
        assert(response.exists("disabledService1"));
        assert(response.getCEntries().size() == 1);

        response = userProvider.getInternalUser("enabledNotService1");
        assert(response.exists("enabledNotService1"));
        assert(response.getCEntries().size() == 1);

        response = userProvider.getInternalUser("passwordHashService1");
        assert(!response.exists("passwordHashService1"));
        assert(response.getCEntries().size() == 0);

        response = userProvider.getInternalUser("passwordService1");
        assert(!response.exists("passwordService1"));
        assert(response.getCEntries().size() == 0);

        response = userProvider.getInternalUser("hashService1");
        assert(!response.exists("hashService1"));
        assert(response.getCEntries().size() == 0);

        userProvider.getInternalUser("");
        assert(response.getCEntries().size() == 3);
    }
}
