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

package org.opensearch.security.test.helper.file;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.hasher.PasswordHasherFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.FipsMode;

/**
 * Test-only helper that rewrites the static bcrypt fixtures and their short demo passwords into
 * FIPS-legal PBKDF2 form, applying the same padding to both the stored hash and the sent password.
 * No-op outside FIPS.
 */
public final class FipsHashAdapter {

    private FipsHashAdapter() {}

    /** Suffix appended to fixture passwords under FIPS so they clear the 14-char (112-bit) PBKDF2 floor. */
    static final String FIPS_PASSWORD_PADDING = "_fips_pw_padding";

    /** Fixture bcrypt hash -&gt; the plaintext it encodes, covering every user any test logs in as. */
    private static final Map<String, String> BCRYPT_HASH_TO_PLAINTEXT = Map.ofEntries(
        // top-level internal_users.yml and the various <resource-folder>/internal_users.yml fixtures
        Map.entry("$2a$04$idGSEpNOhFbyiRL6toGPT.orh7ENOEU8kAqwkRFaXWRdA6wVgyqUu", "user_b"),
        Map.entry("$2a$04$jQcEXpODnTFoGDuA7DPdSevA84CuH/7MOYkb80M3XZIrH76YMWS9G", "user_c"),
        Map.entry("$2a$04$NDy7mGbRNrmPMh9nSnIB.OTMFkcioEd69A04ReSGkJDd7QHxnCcVC", "user_a"),
        Map.entry("$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.", "kibanaserver"),
        Map.entry("$2a$12$61vXe3cXy32p0cjsW0Y/SeZa7kEVSWuQK0jg98D9d5zOGXfo5NgyC", "crusherw"),
        Map.entry("$2a$12$6.4Y6L//xeKQ7t8YEG0s6OH4F4q9gMw0J8E0GjmUMNZeyIWu1IRWS", "user_role01_role02_role03"),
        Map.entry("$2a$12$A41IxPXV1/Dx46C6i1ufGubv.p3qYX7xVcY46q33sylYbIqQVwTMu", "worf"),
        Map.entry("$2a$12$bP0CO5d5nhmaTOj7mGteHugXQQ8jlSV0dxcl5//moZ1xnI.pVPXfe", "abc:abc"),
        Map.entry("$2a$12$GI9JXffO3WUjTsU7Yy3E4.LBxC2ILo66Zg/rr79BpikSL2IIRezQa", "spock"),
        Map.entry("$2a$12$Ioo1uXmH.Nq/lS5dUVBEsePSmZ5pSIpVO/xKHaquU/Jvq97I7nAgG", "sarek"),
        Map.entry("$2a$12$JU2QjYVTlI24Q/enEOpf2uTLCPGchN.eXWCsrBiieUcRoeh53NB0y", "restoreuser"),
        Map.entry("$2a$12$LZvbDVnegkTbEFTu9hHnWO4HIrdB9rGaKcEOID5n0VV4j58cnvyZ.", "writer"),
        Map.entry("$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m", "nagilum"),
        Map.entry("$2a$12$P.QbiwOsnxgz7kLBT10F7u6GhY7//Keyz7Xwf7lNzskRxpo9.zxFS", "theindexadmin"),
        Map.entry("$2a$12$wkY2BsRneCU5za1OPYlzsehQit6gu2vprVv/4jHiSEEBv2ThunaTS", "picard"),
        Map.entry("$2a$12$XrBfLQh2T8wIzpxE5vzhUOPjjGfONcD8UEjd5IT5KveG8ULZaj04.", "user_role01"),
        Map.entry("$2a$12$xZOcnwYPYQ3zIadnlQIJ0eNhX1ngwMkTN.oMwkKxoGvDVPn4/6XtO", "kirk"),
        Map.entry("$2a$12$9Zr4IgoJRqK6xJq4xjoa6OZAnY4QOQ6xIhcCxeYoQtB/HriMkeJSC", "dlsnoinvest"),
        Map.entry("$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG", "admin"),
        Map.entry("$2a$12$1HqHxm3QTfzwkse7vwzhFOV4gDv787cZ8BwmCwNEyJhn0CZoo8VVu", "test"),
        // FLS/DLS caching + indexing fixtures (dlsfls/, cache/)
        Map.entry("$2a$12$7QIoVBGdO41qSCNoecU3L.yyXb9vGrCvEtVlpnC4oWLt/q0AsAN52", "hr_employee"),
        Map.entry("$2a$12$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC", "kibanaro"),
        Map.entry("$2a$12$YCBrpxYyFusK609FurY5Ee3BlmuzWw0qHwpwqEyNhM2.XnQY3Bxpe", "password"),
        Map.entry("$2y$12$SP9z.rBgEHTlueKkiqSK/OxqB2PLJN/eRoNJ8WOPoHWIpirvbFAAy", "password"),
        Map.entry("$2a$12$30rb6oabnodiSdysdWJnhO.4sVRkyNudPC1woYCJFhXja3rkyXbam", "dlsflsuser"),
        Map.entry("$2a$12$Kv.4sU5r1zy2ZqnSDm99Ae6ImCMKtjJq4enT.9d3c55cA0O2LGNH6", "finance_employee"),
        Map.entry("$2a$12$c26Pnq6yiZcgi8PxNEyp5O3wIn1G1eJfCvJFifEKosQJeojUZf/D6", "finance_trainee"),
        Map.entry("$2a$12$LRNG7ETwMcO68VNh14B3AuKPkvOaC0k26.QnSrv9AvbmT1JRNMJum", "hr.employee"),
        Map.entry("$2a$12$s6rC7o345lvXp.JpTrA91O6xYAGVCCxKdVclsNkWJTaquW4GK9E9u", "hr_trainee"),
        Map.entry("$2a$12$gxsE8oEicXy3mNBkGEO5K.P3J/CDq3GHXDYeQTmVI/v3AA84vqIXm", "no_roles"),
        Map.entry("$2a$12$6sre4JH7O4Rgh7ubWmeyWus6UIIA13MqW8eR8KD5Qbxn06CDbJG/G", "snapshotrestore"),
        // rest-api admin fixtures (restapi/)
        Map.entry("$2y$12$ft8tXtxb.dyO/5MrDXHLc.e1o3dktEQJMvR2e.sgVDyD/gR7G9dLS", "admin_all_access"),
        Map.entry("$2y$12$W5AdCO/j08KiDu7EF/1Zf.nkcQM/7s.TtAdN2pRpbDM31xXcIIJUq", "rest_api_admin_allowlist"),
        Map.entry("$2y$12$xFUIepz0vILRMzMkZMGY1Ow1P1eJo8TJ2oGiaFXaenGrOMsmDnKZS", "rest_api_admin_nodesdn"),
        Map.entry("$2y$12$X5ZamIheHYc2bihGTbK66Oe1.1vJ19akH0OFGF7TvI2BhbbED.KcO", "rest_api_admin_user"),
        Map.entry("$2y$12$aHkyhk95XbrMCByYYVAlrek1thXpTDuVKJW01vdLYPh6kyR36j7x6", "user_rest_api_access"),
        Map.entry("$2y$12$xgJfGiHpYOkRpF9W9dXYZOpJJ4bHz3VTwdv7ZZYTwlvx7NbH62qUi", "user_tenant_parameters_substitution"),
        Map.entry("$2y$12$capXg1HNP49Vxeb6ijzRnu5BLMUE0ZePq1l3MhF8tjnuxg614uaY6", "rest_api_admin_config_update"),
        Map.entry("$2y$12$pUn1a6jdIeR.stkvEqNe5uK3rOY7Dj3uQfE8Cvd2bjNjTQ2HbsBMK", "rest_api_admin_internalusers"),
        Map.entry("$2y$12$BR.CBsElNLj8v2dzpHJ7bOKVLwWKWjKDhlEvBIvAe9b6/m0xWy2Bq", "rest_api_admin_roles"),
        Map.entry("$2y$12$irI4k0eKE8z9OXEd1jO4eeQfPV8WRMfttzutAhEeRBWy5XNXOlpr.", "rest_api_admin_ssl_info"),
        Map.entry("$2y$12$DxNdaBBMvTq5wO5XlnwlTeGSaC7yNoFoJt2N5TVtraopxPnGjMol2", "rest_api_admin_ssl_reloadcerts"),
        Map.entry("$2y$12$q05T7m7DFtkLLj.MVJ6jjuZkAywG4ZwaNi9fiYn6XCJelN2TUXCy2", "rest_api_admin_tenants"),
        // index-pattern / protected-indices / system-indices fixtures
        Map.entry("$2y$12$93KcWlQxeify28LSx8EjYOnHv1AQ6vJZXSRUVTnfSN7AxTfvCBfu.", "indexAccessNoRoleUser"),
        Map.entry("$2y$12$LavzCpUFiFwXD22rc0n.SOVExdnzDcn6lHY48XKPl6KKdvAHm0awm", "protectedIndexUser"),
        Map.entry("$2y$12$15ZXoaH/sB.0nESo6VABt.V02HkpA2lQ5QvIFcVqNelUoAdXv1g3O", "negated_regex_user"),
        Map.entry("$2y$12$eaSv29maDe1Y0FQXMHi1legXq8Ec/YbWujMq5Mg2RhYZEc9Pzw19y", "negative_lookahead_user"),
        Map.entry("$2y$12$d1ONiqarfTF9xOuqKeNukeze1bVBXC1FyXJSpuC3B6/Ekbfu3ULHm", "normal_user"),
        Map.entry("$2y$12$V3.ACgUpHP9TlSbV3CNekOGB1NVov1C6Rq3QtXWCvACKVeQnkBCgG", "normal_user_without_system_index")
    );

    /** Distinct plaintext passwords the fixtures use; only these are padded on the credential side. */
    private static final Set<String> KNOWN_PLAINTEXTS = Set.copyOf(BCRYPT_HASH_TO_PLAINTEXT.values());

    private static volatile Map<String, String> bcryptToPbkdf2;

    /** Pads a known fixture password to FIPS-legal length under FIPS; leaves everything else untouched. */
    public static String adaptPassword(final String password) {
        if (password == null || !FipsMode.isEnabled() || !KNOWN_PLAINTEXTS.contains(password)) {
            return password;
        }
        return password + FIPS_PASSWORD_PADDING;
    }

    /** Rewrites known bcrypt fixture hashes to PBKDF2 of the padded plaintext under FIPS; no-op otherwise. */
    public static String adaptConfig(final String content) {
        if (content == null || content.isEmpty() || !FipsMode.isEnabled()) {
            return content;
        }
        String adapted = content;
        for (final Map.Entry<String, String> replacement : pbkdf2Replacements().entrySet()) {
            if (adapted.contains(replacement.getKey())) {
                adapted = adapted.replace(replacement.getKey(), replacement.getValue());
            }
        }
        return adapted;
    }

    /** Rewrites a config file's hashes to PBKDF2 in place under FIPS, for init paths that read it from disk. */
    public static void adaptConfigFile(final File file) throws IOException {
        Files.writeString(file.toPath(), adaptConfig(Files.readString(file.toPath(), StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    /** Lazily builds the {@code bcrypt -> PBKDF2} table using the FIPS node's default PBKDF2 params. */
    private static Map<String, String> pbkdf2Replacements() {
        Map<String, String> local = bcryptToPbkdf2;
        if (local == null) {
            synchronized (FipsHashAdapter.class) {
                local = bcryptToPbkdf2;
                if (local == null) {
                    final PasswordHasher hasher = PasswordHasherFactory.createPasswordHasher(
                        Settings.builder().put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.PBKDF2).build()
                    );
                    final Map<String, String> table = new HashMap<>();
                    for (final Map.Entry<String, String> entry : BCRYPT_HASH_TO_PLAINTEXT.entrySet()) {
                        table.put(entry.getKey(), hasher.hash(adaptPassword(entry.getValue()).toCharArray()));
                    }
                    bcryptToPbkdf2 = local = Map.copyOf(table);
                }
            }
        }
        return local;
    }
}
