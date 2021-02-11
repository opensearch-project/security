package com.amazon.opendistroforelasticsearch.security.user;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UserTests {

    Set<String> opendistroSecurityRoles = new HashSet();

    @Test
    public void testUsersCopy() {
        opendistroSecurityRoles.add("role_1");

        User user = new User("test_user", "auth_token", null, opendistroSecurityRoles, null, "some_random_id");

        User copyUser = user.copy().build();

        Assert.assertEquals(user.getName(), copyUser.getName());
        Assert.assertEquals(user.getRoles(), copyUser.getRoles());
        Assert.assertEquals(user.getOpenDistroSecurityRoles(), copyUser.getOpenDistroSecurityRoles());
        Assert.assertEquals(user.getType(), copyUser.getType());
    }

    @Test
    public void testUserBuilder() {
        User.Builder builder = new User.Builder();
        builder.openDistroSecurityRoles(opendistroSecurityRoles);

        opendistroSecurityRoles.add("role_1");
        builder.backendRoles(opendistroSecurityRoles);

        String userType = "auth_token";
        builder.type(userType);

        builder.name("auth_token_");

        User user = builder.build();

        Assert.assertEquals(user.getName(), "auth_token_");
        Assert.assertEquals(user.getType(), userType);
        Assert.assertEquals(user.getOpenDistroSecurityRoles().size(), 0);
        Assert.assertEquals(user.getRoles().size(), 1);


    }


}
