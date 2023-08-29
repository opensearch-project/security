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

package org.opensearch.security.tools;

import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

/**
 * This tool helps generate checksums for demo certs
 * Refer here: {@link org.opensearch.security.OpenSearchSecurityPlugin#demoCertHashes}
 */
public class ChecksumCalculator {
    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("Usage: java ChecksumCalculator <folder_path_to_certificate_file> <file_extension>");
            System.exit(1);
        }

        // Get the path to the certificate file from the command-line argument.
        String folderPath = args[0];
        String fileExtension = args[1];
        Path p = Path.of(folderPath);
        System.out.println("Certificate Hash (SHA-256): ");
        sha256(p, fileExtension);
    }

    /**
     * Generate SHA 256 hash for all file with given extension in provided folder
     *
     * @param folderPath    path to certificate file
     * @param fileExtension extension of the certificate file
     */
    private static void sha256(Path folderPath, String fileExtension) throws IOException {

        // Walk through the directory and filter for PEM files.
        try (
            Stream<Path> pemFiles = Files.walk(folderPath, 1)
                .filter(path -> Files.isRegularFile(path) && path.getFileName().toString().toLowerCase().endsWith(fileExtension))
        ) {

            // Initialize the digester with the desired hash algorithm (SHA-256).
            SHA256.Digest digester = new SHA256.Digest();

            // Calculate and print the hash for each PEM file.
            pemFiles.forEach(pemFile -> {
                try {
                    byte[] pemBytes = Files.readAllBytes(pemFile);
                    byte[] hash = digester.digest(pemBytes);
                    String hexHash = Hex.toHexString(hash);
                    System.out.println("File: " + pemFile.getFileName() + ", Hash (SHA-256): " + hexHash);
                } catch (IOException e) {
                    // do nothing
                }
            });
        }
    }
}
