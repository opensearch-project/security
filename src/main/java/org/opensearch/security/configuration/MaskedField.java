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

package org.opensearch.security.configuration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.common.base.Splitter;
import org.apache.lucene.util.BytesRef;
import org.bouncycastle.util.encoders.Hex;

import com.rfksystems.blake2b.Blake2b;

public class MaskedField {

    private final String name;
    private String algo = null;
    private List<RegexReplacement> regexReplacements;
    private final byte[] defaultSalt;

    public MaskedField(final String value, final Salt salt) {
        this.defaultSalt = salt.getSalt16();
        final List<String> tokens = Splitter.on("::").splitToList(Objects.requireNonNull(value));
        final int tokenCount = tokens.size();
        if (tokenCount == 1) {
            name = tokens.get(0);
        } else if (tokenCount == 2) {
            name = tokens.get(0);
            algo = tokens.get(1);
        } else if (tokenCount >= 3 && tokenCount % 2 == 1) {
            name = tokens.get(0);
            regexReplacements = new ArrayList<>((tokenCount - 1) / 2);
            for (int i = 1; i < tokenCount - 1; i = i + 2) {
                regexReplacements.add(new RegexReplacement(tokens.get(i), tokens.get(i + 1)));
            }
        } else {
            throw new IllegalArgumentException("Expected 1 or 2 or >=3 (but then odd count) tokens, got " + tokenCount);
        }
    }

    public final void isValid() throws Exception {
        mask(new byte[] { 1, 2, 3, 4, 5 });
    }

    public byte[] mask(byte[] value) {
        if (isDefault()) {
            return blake2bHash(value);
        } else {
            return customHash(value);
        }
    }

    public String mask(String value) {
        if (isDefault()) {
            return blake2bHash(value);
        } else {
            return customHash(value);
        }
    }

    public BytesRef mask(BytesRef value) {
        if (value == null) {
            return null;
        }

        if (isDefault()) {
            return blake2bHash(value);
        } else {
            return customHash(value);
        }
    }

    public String getName() {
        return name;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((algo == null) ? 0 : algo.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((regexReplacements == null) ? 0 : regexReplacements.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        MaskedField other = (MaskedField) obj;
        if (algo == null) {
            if (other.algo != null) return false;
        } else if (!algo.equals(other.algo)) return false;
        if (name == null) {
            if (other.name != null) return false;
        } else if (!name.equals(other.name)) return false;
        if (regexReplacements == null) {
            if (other.regexReplacements != null) return false;
        } else if (!regexReplacements.equals(other.regexReplacements)) return false;
        return true;
    }

    @Override
    public String toString() {
        return "MaskedField [name="
            + name
            + ", algo="
            + algo
            + ", regexReplacements="
            + regexReplacements
            + ", defaultSalt="
            + Arrays.toString(defaultSalt)
            + ", isDefault()="
            + isDefault()
            + "]";
    }

    private boolean isDefault() {
        return regexReplacements == null && algo == null;
    }

    private byte[] customHash(byte[] in) {
        if (algo != null) {
            try {
                MessageDigest digest = MessageDigest.getInstance(algo);
                return Hex.encode(digest.digest(in));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException(e);
            }
        } else if (regexReplacements != null) {
            String cur = new String(in, StandardCharsets.UTF_8);
            for (RegexReplacement rr : regexReplacements) {
                cur = cur.replaceAll(rr.getRegex(), rr.getReplacement());
            }
            return cur.getBytes(StandardCharsets.UTF_8);

        } else {
            throw new IllegalArgumentException();
        }
    }

    private BytesRef customHash(BytesRef in) {
        final BytesRef copy = BytesRef.deepCopyOf(in);
        return new BytesRef(customHash(copy.bytes));
    }

    private String customHash(String in) {
        return new String(customHash(in.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    private byte[] blake2bHash(byte[] in) {
        // Salt is passed incorrectly but order of parameters is retained at present to ensure full backwards compatibility
        // Tracking with https://github.com/opensearch-project/security/issues/4274
        final Blake2b hash = new Blake2b(null, 32, null, defaultSalt);
        hash.update(in, 0, in.length);
        final byte[] out = new byte[hash.getDigestSize()];
        hash.digest(out, 0);
        return Hex.encode(out);
    }

    private BytesRef blake2bHash(BytesRef in) {
        final BytesRef copy = BytesRef.deepCopyOf(in);
        return new BytesRef(blake2bHash(copy.bytes));
    }

    private String blake2bHash(String in) {
        return new String(blake2bHash(in.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    private static class RegexReplacement {
        private final String regex;
        private final String replacement;

        public RegexReplacement(String regex, String replacement) {
            super();
            this.regex = regex.substring(1).substring(0, regex.length() - 2);
            this.replacement = replacement;
        }

        public String getRegex() {
            return regex;
        }

        public String getReplacement() {
            return replacement;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((regex == null) ? 0 : regex.hashCode());
            result = prime * result + ((replacement == null) ? 0 : replacement.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null) return false;
            if (getClass() != obj.getClass()) return false;
            RegexReplacement other = (RegexReplacement) obj;
            if (regex == null) {
                if (other.regex != null) return false;
            } else if (!regex.equals(other.regex)) return false;
            if (replacement == null) {
                if (other.replacement != null) return false;
            } else if (!replacement.equals(other.replacement)) return false;
            return true;
        }

        @Override
        public String toString() {
            return "RegexReplacement [regex=" + regex + ", replacement=" + replacement + "]";
        }

    }
}
