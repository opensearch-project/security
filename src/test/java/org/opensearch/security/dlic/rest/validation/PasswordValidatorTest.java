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

package org.opensearch.security.dlic.rest.validation;

import java.util.List;

import com.google.common.collect.ImmutableList;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX;
import static org.junit.Assert.assertEquals;

public class PasswordValidatorTest {

    static final List<String> WEAK_PASSWORDS = ImmutableList.of("q", "5", "&", "admin", "123456", "password");

    static final List<String> FAIR_PASSWORDS = ImmutableList.of(
        "p@$$word@dmin",
        "qwertyuiop@[",
        "zxcvbnm,./_",
        "asdfghjkl;:]",
        "20300101",
        "pandapandapandapandapandapandapandapandapandaa",
        "appleappleappleappleappleappleappleappleapplea",
        "aelppaaelppaaelppaaelppaaelppaaelppaaelppaaelppa"
    );

    static final List<String> GOOD_PASSWORDS = ImmutableList.of(
        "xsw234rfvb",
        "yaq123edc",
        "cde345tgbn",
        "yaqwedcvb",
        "Tr0ub4dour&3",
        "qwER43@!"
    );

    static final List<String> STRONG_PASSWORDS = ImmutableList.of("YWert,H90", "Admincc,H90", "Hadmin,120");

    static final List<String> VERY_STRONG_PASSWORDS = ImmutableList.of(
        "AeTq($%u-44c_j9NJB45a#2#JP7sH",
        "IB7~EOw!51gug+7s#+%A9P1O/w8f",
        "1v_f%7JvS8w!_t398+ON-CObI#v0",
        "8lFmfc0!w)&iU9DM6~4_w)D)Y44J"
    );

    static final List<String> SIMILAR_PASSWORDS = ImmutableList.of(
        "some_user_name,H2344cc",
        "H3235,Some_User_Name,cc",
        "H3235,cc,some_User_Name",
        "H3235,SOME_User_Name,cc",
        "H3235,eman_resu_emos,cc"
    );

    public void verifyWeakPasswords(
        final PasswordValidator passwordValidator,
        final RequestContentValidator.ValidationError expectedValidationResult
    ) {
        for (final String password : WEAK_PASSWORDS)
            assertEquals(password, expectedValidationResult, passwordValidator.validate("some_user_name", password));

    }

    public void verifyFairPasswords(
        final PasswordValidator passwordValidator,
        final RequestContentValidator.ValidationError expectedValidationResult
    ) {
        for (final String password : FAIR_PASSWORDS)
            assertEquals(password, expectedValidationResult, passwordValidator.validate("some_user_name", password));

    }

    public void verifyGoodPasswords(
        final PasswordValidator passwordValidator,
        final RequestContentValidator.ValidationError expectedValidationResult
    ) {
        for (final String password : GOOD_PASSWORDS)
            assertEquals(password, expectedValidationResult, passwordValidator.validate("some_user_name", password));

    }

    public void verifyStrongPasswords(
        final PasswordValidator passwordValidator,
        final RequestContentValidator.ValidationError expectedValidationResult
    ) {
        for (final String password : STRONG_PASSWORDS)
            assertEquals(password, expectedValidationResult, passwordValidator.validate("some_user_name", password));

    }

    public void verifyVeryStrongPasswords(
        final PasswordValidator passwordValidator,
        final RequestContentValidator.ValidationError expectedValidationResult
    ) {
        for (final String password : VERY_STRONG_PASSWORDS)
            assertEquals(password, expectedValidationResult, passwordValidator.validate("some_user_name", password));

    }

    public void verifySimilarPasswords(final PasswordValidator passwordValidator) {
        for (final String password : SIMILAR_PASSWORDS)
            assertEquals(
                password,
                RequestContentValidator.ValidationError.SIMILAR_PASSWORD,
                passwordValidator.validate("some_user_name", password)
            );

    }

    @Test
    public void testRegExpBasedValidation() {
        final PasswordValidator passwordValidator = PasswordValidator.of(
            Settings.builder()
                .put(SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, "(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}")
                .build()
        );
        verifyWeakPasswords(passwordValidator, RequestContentValidator.ValidationError.INVALID_PASSWORD_INVALID_REGEX);
        verifyFairPasswords(passwordValidator, RequestContentValidator.ValidationError.INVALID_PASSWORD_INVALID_REGEX);
        for (final String password : GOOD_PASSWORDS.subList(0, GOOD_PASSWORDS.size() - 2))
            assertEquals(
                password,
                RequestContentValidator.ValidationError.INVALID_PASSWORD_INVALID_REGEX,
                passwordValidator.validate("some_user_name", password)
            );
        for (final String password : GOOD_PASSWORDS.subList(GOOD_PASSWORDS.size() - 2, GOOD_PASSWORDS.size()))
            assertEquals(
                password,
                RequestContentValidator.ValidationError.WEAK_PASSWORD,
                passwordValidator.validate("some_user_name", password)
            );
        verifyStrongPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifyVeryStrongPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifySimilarPasswords(passwordValidator);
    }

    @Test
    public void testMinLength() {
        final PasswordValidator passwordValidator = PasswordValidator.of(
            Settings.builder().put(SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, 15).build()
        );
        for (final String password : STRONG_PASSWORDS) {
            assertEquals(
                RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT,
                passwordValidator.validate(password, "some_user_name")
            );
        }

    }

    @Test
    public void testScoreBasedValidation() {
        PasswordValidator passwordValidator = PasswordValidator.of(Settings.EMPTY);
        verifyWeakPasswords(passwordValidator, RequestContentValidator.ValidationError.WEAK_PASSWORD);
        verifyFairPasswords(passwordValidator, RequestContentValidator.ValidationError.WEAK_PASSWORD);
        verifyGoodPasswords(passwordValidator, RequestContentValidator.ValidationError.WEAK_PASSWORD);
        verifyStrongPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifyVeryStrongPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifySimilarPasswords(passwordValidator);

        passwordValidator = PasswordValidator.of(
            Settings.builder()
                .put(SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH, PasswordValidator.ScoreStrength.FAIR.name())
                .build()
        );

        verifyWeakPasswords(passwordValidator, RequestContentValidator.ValidationError.WEAK_PASSWORD);
        verifyFairPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifyGoodPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifyStrongPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifyVeryStrongPasswords(passwordValidator, RequestContentValidator.ValidationError.NONE);
        verifySimilarPasswords(passwordValidator);
    }

}
