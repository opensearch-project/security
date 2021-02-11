package com.amazon.opendistroforelasticsearch.security.user;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class AuthCredentialsTests {
  @Test
  public void testEquality() {
    Assert.assertEquals(
      new AuthCredentials("george", "admin"),
      new AuthCredentials("george", "admin"));
    Assert.assertNotEquals(
      new AuthCredentials("george", "admin"),
      new AuthCredentials("george", "not_admin"));
    Assert.assertNotEquals(
      new AuthCredentials("fred", "admin"),
      new AuthCredentials("george", "admin"));

    Assert.assertEquals(
        new AuthCredentials("george", "secret".getBytes()),
        new AuthCredentials("george", "secret".getBytes()));
    Assert.assertNotEquals(
        new AuthCredentials("george", "secret".getBytes()),
        new AuthCredentials("george", "hunter2".getBytes()));

    // If one AuthCredentials has a password and the other has a native credentials, they should
    // not be equal.
    Assert.assertNotEquals(
        new AuthCredentials("george", "secret".getBytes()),
        new AuthCredentials("george", "admin"));
  }

    @Test
    public void testAuthCredentialsBuilder() {
        AuthCredentials.Builder builder = AuthCredentials.forUser("test_user");
        builder.backendRoles("role1", "role2");


        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "test_user");
        claims.put("aud", "opendistro_security_authtoken");
        claims.put("jti", "some_random_identifier");

        builder.claims(claims);

        AuthCredentials authCredentials = builder.authzComplete().build();

        Assert.assertEquals(authCredentials.getBackendRoles().size(), 2);
        Assert.assertEquals(authCredentials.getUsername(), "test_user");
        Assert.assertEquals(authCredentials.getClaims(), claims);
    }
}
