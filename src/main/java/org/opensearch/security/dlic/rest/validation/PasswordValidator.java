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
import java.util.Locale;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import com.nulabinc.zxcvbn.matchers.Match;

import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_MIN_LENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX;

public class PasswordValidator {

    private static final int MAX_LENGTH = 100;

    /**
     * Checks a username similarity and a password
     * names and passwords like:
     *  - some_user_name/456Some_uSer_Name_1234
     *  - some_user_name/some_user_name_Ydfge
     *  - some_user_name/eman_resu_emos
     *  are similar
     * "user_inputs" - is a default dictionary zxcvbn creates for checking similarity
     */
    private final static Predicate<Match> USERNAME_SIMILARITY_CHECK = m -> m.pattern == com.nulabinc.zxcvbn.Pattern.Dictionary
        && "user_inputs".equals(m.dictionaryName);

    private final Logger logger = LogManager.getLogger(this.getClass());

    private final int minPasswordLength;

    private final Pattern passwordRegexpPattern;

    private final ScoreStrength scoreStrength;

    private final Zxcvbn zxcvbn;

    private PasswordValidator(final int minPasswordLength, final Pattern passwordRegexpPattern, final ScoreStrength scoreStrength) {
        this.minPasswordLength = minPasswordLength;
        this.passwordRegexpPattern = passwordRegexpPattern;
        this.scoreStrength = scoreStrength;
        this.zxcvbn = new Zxcvbn();
    }

    public static PasswordValidator of(final Settings settings) {
        final String passwordRegex = settings.get(SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, null);
        final ScoreStrength scoreStrength = ScoreStrength.fromConfiguration(
            settings.get(SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH, ScoreStrength.STRONG.name())
        );
        final int minPasswordLength = settings.getAsInt(SECURITY_RESTAPI_PASSWORD_MIN_LENGTH, -1);
        return new PasswordValidator(
            minPasswordLength,
            !Strings.isNullOrEmpty(passwordRegex) ? Pattern.compile(String.format("^%s$", passwordRegex)) : null,
            scoreStrength
        );
    }

    public RequestContentValidator.ValidationError validate(final String username, final String password) {
        if (minPasswordLength > 0 && password.length() < minPasswordLength) {
            logger.debug(
                "Password is too short, the minimum required length is {}, but current length is {}",
                minPasswordLength,
                password.length()
            );
            return RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_SHORT;
        }
        if (password.length() > MAX_LENGTH) {
            logger.debug(
                "Password is too long, the maximum required length is {}, but current length is {}",
                MAX_LENGTH,
                password.length()
            );
            return RequestContentValidator.ValidationError.INVALID_PASSWORD_TOO_LONG;
        }
        if (Objects.nonNull(passwordRegexpPattern) && !passwordRegexpPattern.matcher(password).matches()) {
            logger.debug("Regex does not match password");
            return RequestContentValidator.ValidationError.INVALID_PASSWORD_INVALID_REGEX;
        }
        final Strength strength = zxcvbn.measure(password, ImmutableList.of(username));
        if (strength.getScore() < scoreStrength.score()) {
            logger.debug(
                "Password is weak the required score is {}, but current is {}",
                scoreStrength,
                ScoreStrength.fromScore(strength.getScore())
            );
            return RequestContentValidator.ValidationError.WEAK_PASSWORD;
        }
        final boolean similar = strength.getSequence().stream().anyMatch(USERNAME_SIMILARITY_CHECK);
        if (similar) {
            logger.debug("Password is too similar to the user name {}", username);
            return RequestContentValidator.ValidationError.SIMILAR_PASSWORD;
        }
        return RequestContentValidator.ValidationError.NONE;
    }

    public enum ScoreStrength {

        // The weak score defines here only for debugging information
        // and doesn't use as a configuration setting value.
        WEAK(0, "too guessable: risky password"),
        FAIR(1, "very guessable: protection from throttled online attacks"),
        GOOD(2, "somewhat guessable: protection from unthrottled online attacks"),
        STRONG(3, "safely unguessable: moderate protection from offline slow-hash scenario"),
        VERY_STRONG(4, "very unguessable: strong protection from offline slow-hash scenario");

        private final int score;

        private final String description;

        static final List<ScoreStrength> CONFIGURATION_VALUES = ImmutableList.of(FAIR, STRONG, VERY_STRONG);

        static final String EXPECTED_CONFIGURATION_VALUES = new StringJoiner(",").add(FAIR.name().toLowerCase(Locale.ROOT))
            .add(STRONG.name().toLowerCase(Locale.ROOT))
            .add(VERY_STRONG.name().toLowerCase(Locale.ROOT))
            .toString();

        private ScoreStrength(final int score, final String description) {
            this.score = score;
            this.description = description;
        }

        public static ScoreStrength fromScore(final int score) {
            for (final ScoreStrength strength : values()) {
                if (strength.score == score) return strength;
            }
            throw new IllegalArgumentException("Unknown score " + score);
        }

        public static ScoreStrength fromConfiguration(final String value) {
            for (final ScoreStrength strength : CONFIGURATION_VALUES) {
                if (strength.name().equalsIgnoreCase(value)) return strength;
            }
            throw new IllegalArgumentException(
                String.format(
                    "Setting [%s] cannot be used with the configured: %s. Expected one of [%s]",
                    SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH,
                    value,
                    EXPECTED_CONFIGURATION_VALUES
                )
            );
        }

        @Override
        public String toString() {
            return String.format("Password strength score %s. %s", score, description);
        }

        public int score() {
            return this.score;
        }

    }
}
