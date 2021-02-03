package com.amazon.opendistroforelasticsearch.security.user;

import org.junit.Assert;
import org.junit.Test;

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
}
