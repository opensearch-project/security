/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auth;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;

import org.mockito.Mockito;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class InternalAuthBackendTests {

    private InternalUsersModel internalUsersModel;

    private InternalAuthenticationBackend internalAuthenticationBackend;

    @Before
    public void internalAuthBackendTestsSetup() {
        internalAuthenticationBackend = spy(
            new InternalAuthenticationBackend(
                PasswordHasherFactory.createPasswordHasher(
                    Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT).build()
                )
            )
        );
        internalUsersModel = mock(InternalUsersModel.class);
        internalAuthenticationBackend.onInternalUsersModelChanged(internalUsersModel);
    }

    private char[] createArrayFromPasswordBytes(byte[] password) {
        ByteBuffer wrap = ByteBuffer.wrap(password);
        CharBuffer buf = StandardCharsets.UTF_8.decode(wrap);
        char[] array = new char[buf.limit()];
        buf.get(array);
        Arrays.fill(password, (byte) 0);
        return array;
    }

    @Test
    public void testHashActionWithValidUserValidPassword() {

        // Make authentication info for valid username with valid password
        final String validPassword = "admin";
        final byte[] validPasswordBytes = validPassword.getBytes();

        final AuthCredentials validUsernameAuth = new AuthCredentials("admin", validPasswordBytes);

        final String hash = "$2y$12$NmKhjNssNgSIj8iXT7SYxeXvMA1E95a9tCt4cySY9FrQ4fB18xEc2";

        char[] array = createArrayFromPasswordBytes(validPasswordBytes);

        when(internalUsersModel.getHash(validUsernameAuth.getUsername())).thenReturn(hash);
        when(internalUsersModel.exists(validUsernameAuth.getUsername())).thenReturn(true);
        when(internalUsersModel.getAttributes(validUsernameAuth.getUsername())).thenReturn(ImmutableMap.of());
        when(internalUsersModel.getSecurityRoles(validUsernameAuth.getUsername())).thenReturn(ImmutableSet.of());
        when(internalUsersModel.getBackendRoles(validUsernameAuth.getUsername())).thenReturn(ImmutableSet.of());

        doReturn(true).when(internalAuthenticationBackend).passwordMatchesHash(Mockito.any(String.class), Mockito.any(char[].class));

        // Act
        internalAuthenticationBackend.authenticate(new AuthenticationContext(validUsernameAuth));

        verify(internalAuthenticationBackend, times(1)).passwordMatchesHash(hash, array);
        verify(internalUsersModel, times(1)).getBackendRoles(validUsernameAuth.getUsername());
    }

    @Test
    public void testHashActionWithValidUserInvalidPassword() {

        // Make authentication info for valid with bad password
        final String gibberishPassword = "ajdhflkasdjfaklsdf";
        final byte[] gibberishPasswordBytes = gibberishPassword.getBytes();
        final AuthCredentials validUsernameAuth = new AuthCredentials("admin", gibberishPasswordBytes);

        final String hash = "$2y$12$NmKhjNssNgSIj8iXT7SYxeXvMA1E95a9tCt4cySY9FrQ4fB18xEc2";

        char[] array = createArrayFromPasswordBytes(gibberishPasswordBytes);

        when(internalUsersModel.getHash("admin")).thenReturn(hash);
        when(internalUsersModel.exists("admin")).thenReturn(true);

        OpenSearchSecurityException ex = Assert.assertThrows(
            OpenSearchSecurityException.class,
            () -> internalAuthenticationBackend.authenticate(new AuthenticationContext(validUsernameAuth))
        );
        assert (ex.getMessage().contains("password does not match"));
        verify(internalAuthenticationBackend, times(1)).passwordMatchesHash(hash, array);
    }

    @Test
    public void testHashActionWithInvalidUserValidPassword() {

        // Make authentication info for valid and invalid usernames both with bad passwords
        final String validPassword = "admin";
        final byte[] validPasswordBytes = validPassword.getBytes();
        final AuthCredentials invalidUsernameAuth = new AuthCredentials("ertyuiykgjjfguyifdghc", validPasswordBytes);

        final String hash = "$2y$12$NmKhjNssNgSIj8iXT7SYxeXvMA1E95a9tCt4cySY9FrQ4fB18xEc2";

        char[] array = createArrayFromPasswordBytes(validPasswordBytes);

        when(internalUsersModel.exists("ertyuiykgjjfguyifdghc")).thenReturn(false);
        when(internalAuthenticationBackend.passwordMatchesHash(hash, array)).thenReturn(true); // Say that the password is correct

        OpenSearchSecurityException ex = Assert.assertThrows(
            OpenSearchSecurityException.class,
            () -> internalAuthenticationBackend.authenticate(new AuthenticationContext(invalidUsernameAuth))
        );
        assert (ex.getMessage().contains("not found"));
        verify(internalAuthenticationBackend, times(1)).passwordMatchesHash(hash, array);
    }

    @Test
    public void testHashActionWithInvalidUserInvalidPassword() {

        // Make authentication info for valid and invalid usernames both with bad passwords
        final String gibberishPassword = "ajdhflkasdjfaklsdf";
        final byte[] gibberishPasswordBytes = gibberishPassword.getBytes();
        final AuthCredentials invalidUsernameAuth = new AuthCredentials("ertyuiykgjjfguyifdghc", gibberishPasswordBytes);

        final String hash = "$2y$12$NmKhjNssNgSIj8iXT7SYxeXvMA1E95a9tCt4cySY9FrQ4fB18xEc2";

        char[] array = createArrayFromPasswordBytes(gibberishPasswordBytes);

        when(internalUsersModel.exists("ertyuiykgjjfguyifdghc")).thenReturn(false);

        OpenSearchSecurityException ex = Assert.assertThrows(
            OpenSearchSecurityException.class,
            () -> internalAuthenticationBackend.authenticate(new AuthenticationContext(invalidUsernameAuth))
        );
        verify(internalAuthenticationBackend, times(1)).passwordMatchesHash(hash, array);
        assert (ex.getMessage().contains("not found"));
    }

    // -- userExists() -- pre-BCrypt early-notify gating ------------------------

    @Test
    public void userExistsReturnsTrueWhenUserPresent() {
        // Backend reports "user present" so the caller skips the early-notify
        // path and proceeds straight to authcz() / BCrypt.
        when(internalUsersModel.exists("admin")).thenReturn(true);

        java.util.Optional<Boolean> result = internalAuthenticationBackend.userExists("admin");
        Assert.assertTrue("Optional.isPresent()", result.isPresent());
        Assert.assertEquals("admin should exist", Boolean.TRUE, result.get());
    }

    @Test
    public void userExistsReturnsFalseWhenUserAbsent() {
        // The "user does not exist" path is the one that triggers
        // BackendRegistry.earlyFailureNotified -- IP rate limiter increments
        // BEFORE the (constant-time-anti-enumeration) BCrypt fires.
        when(internalUsersModel.exists("ghost")).thenReturn(false);

        java.util.Optional<Boolean> result = internalAuthenticationBackend.userExists("ghost");
        Assert.assertTrue("Optional.isPresent()", result.isPresent());
        Assert.assertEquals("ghost should not exist", Boolean.FALSE, result.get());
    }

    @Test
    public void userExistsReturnsEmptyBeforeModelInitialized() {
        // Early in startup / config reload the InternalUsersModel can be transiently
        // null. userExists() must NOT throw (would crash the auth path) and must
        // return Optional.empty so the caller skips the early-notify optimization
        // and falls through to authenticate(). The local capture in the
        // implementation is what makes this safe even if onInternalUsersModelChanged
        // fires concurrently.
        InternalAuthenticationBackend freshBackend = spy(
            new InternalAuthenticationBackend(
                PasswordHasherFactory.createPasswordHasher(
                    Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT).build()
                )
            )
        );
        // No onInternalUsersModelChanged() -- model stays null.
        java.util.Optional<Boolean> result = freshBackend.userExists("anyone");
        Assert.assertFalse("Optional.empty() before model init", result.isPresent());
    }
}
