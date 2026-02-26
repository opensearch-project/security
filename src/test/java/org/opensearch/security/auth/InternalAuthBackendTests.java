/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auth;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;
import org.opensearch.security.hasher.PasswordHasher;
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

@RunWith(Parameterized.class)
public class InternalAuthBackendTests {

    private final Settings settings;

    private InternalUsersModel internalUsersModel;
    private InternalAuthenticationBackend internalAuthenticationBackend;
    private PasswordHasher passwordHasher;
    private String storedHash;

    public InternalAuthBackendTests(String algorithmName, Settings settings) {
        this.settings = settings;
    }

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> hashingAlgorithms() {
        return Arrays.asList(new Object[][] {
            {
                "BCrypt",
                Settings.builder()
                    .put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.BCRYPT)
                    .put(ConfigConstants.SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS, 4)
                    .build()
            },
            {
                "PBKDF2",
                Settings.builder()
                    .put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.PBKDF2)
                    .put(ConfigConstants.SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS, 1)
                    .build()
            },
            {
                "Argon2",
                Settings.builder()
                    .put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.ARGON2)
                    .put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_MEMORY, 8)
                    .put(ConfigConstants.SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS, 1)
                    .build()
            }
        });
    }

    @Before
    public void internalAuthBackendTestsSetup() {
        passwordHasher = PasswordHasherFactory.createPasswordHasher(settings);
        storedHash = passwordHasher.hash("$adminpassword!".toCharArray());
        internalAuthenticationBackend = spy(new InternalAuthenticationBackend(passwordHasher));
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
        final String validPassword = "$adminpassword!";
        final byte[] validPasswordBytes = validPassword.getBytes();

        final AuthCredentials validUsernameAuth = new AuthCredentials("$adminpassword!", validPasswordBytes);

        char[] array = createArrayFromPasswordBytes(validPasswordBytes);

        when(internalUsersModel.getHash(validUsernameAuth.getUsername())).thenReturn(storedHash);
        when(internalUsersModel.exists(validUsernameAuth.getUsername())).thenReturn(true);
        when(internalUsersModel.getAttributes(validUsernameAuth.getUsername())).thenReturn(ImmutableMap.of());
        when(internalUsersModel.getSecurityRoles(validUsernameAuth.getUsername())).thenReturn(ImmutableSet.of());
        when(internalUsersModel.getBackendRoles(validUsernameAuth.getUsername())).thenReturn(ImmutableSet.of());

        doReturn(true).when(internalAuthenticationBackend).passwordMatchesHash(Mockito.any(String.class), Mockito.any(char[].class));

        // Act
        internalAuthenticationBackend.authenticate(new AuthenticationContext(validUsernameAuth));

        verify(internalAuthenticationBackend, times(1)).passwordMatchesHash(storedHash, array);
        verify(internalUsersModel, times(1)).getBackendRoles(validUsernameAuth.getUsername());
    }

    @Test
    public void testHashActionWithValidUserInvalidPassword() {

        // Make authentication info for valid with bad password
        final String gibberishPassword = "ajdhflkasdjfaklsdf";
        final byte[] gibberishPasswordBytes = gibberishPassword.getBytes();
        final AuthCredentials validUsernameAuth = new AuthCredentials("$adminpassword!", gibberishPasswordBytes);

        char[] array = createArrayFromPasswordBytes(gibberishPasswordBytes);

        when(internalUsersModel.getHash("$adminpassword!")).thenReturn(storedHash);
        when(internalUsersModel.exists("$adminpassword!")).thenReturn(true);

        OpenSearchSecurityException ex = Assert.assertThrows(
            OpenSearchSecurityException.class,
            () -> internalAuthenticationBackend.authenticate(new AuthenticationContext(validUsernameAuth))
        );
        assert (ex.getMessage().contains("password does not match"));
        verify(internalAuthenticationBackend, times(1)).passwordMatchesHash(storedHash, array);
    }

    @Test
    public void testHashActionWithInvalidUserValidPassword() {

        // Make authentication info for valid and invalid usernames both with bad passwords
        final String validPassword = "$adminpassword!";
        final byte[] validPasswordBytes = validPassword.getBytes();
        final AuthCredentials invalidUsernameAuth = new AuthCredentials("ertyuiykgjjfguyifdghc", validPasswordBytes);

        final String hash = passwordHasher.getDummyHash();

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

        final String hash = passwordHasher.getDummyHash();

        char[] array = createArrayFromPasswordBytes(gibberishPasswordBytes);

        when(internalUsersModel.exists("ertyuiykgjjfguyifdghc")).thenReturn(false);

        OpenSearchSecurityException ex = Assert.assertThrows(
            OpenSearchSecurityException.class,
            () -> internalAuthenticationBackend.authenticate(new AuthenticationContext(invalidUsernameAuth))
        );
        verify(internalAuthenticationBackend, times(1)).passwordMatchesHash(hash, array);
        assert (ex.getMessage().contains("not found"));
    }
}
