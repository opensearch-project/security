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

package org.opensearch.security;

import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assume.assumeTrue;

/**
 * Tests for the config directory permission check performed on startup. The check must follow symlinks so that
 * the permissions of the file that is actually read are the ones being validated, see
 * https://github.com/opensearch-project/security/issues/1891.
 */
public class OpenSearchSecurityPluginFilePermissionsTest extends LuceneTestCase {

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    private OpenSearchSecurityPlugin plugin;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        assumeTrue("Requires a POSIX filesystem", FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        // The plugin short-circuits its constructor when disabled, which keeps this a plain unit test.
        plugin = new OpenSearchSecurityPlugin(Settings.builder().put(ConfigConstants.SECURITY_DISABLED, true).build(), null);
    }

    @Test
    public void nullPathIsNotFlagged() {
        assertThat(plugin.checkFilePermissions(null), equalTo(false));
    }

    @Test
    public void fileWithSecurePermissionsIsNotFlagged() throws Exception {
        assertThat(plugin.checkFilePermissions(file("secure", "rw-------")), equalTo(false));
    }

    @Test
    public void fileReadableByOthersIsFlagged() throws Exception {
        assertThat(plugin.checkFilePermissions(file("others-read", "rw----r--")), equalTo(true));
    }

    @Test
    public void fileWritableByOthersIsFlagged() throws Exception {
        assertThat(plugin.checkFilePermissions(file("others-write", "rw-----w-")), equalTo(true));
    }

    @Test
    public void executableFileIsFlagged() throws Exception {
        assertThat(plugin.checkFilePermissions(file("executable", "rwx------")), equalTo(true));
    }

    @Test
    public void directoryWithSecurePermissionsIsNotFlagged() throws Exception {
        assertThat(plugin.checkFilePermissions(directory("secure-dir", "rwx------")), equalTo(false));
    }

    @Test
    public void directoryExecutableByOthersIsFlagged() throws Exception {
        assertThat(plugin.checkFilePermissions(directory("others-exec-dir", "rwx---r-x")), equalTo(true));
    }

    /**
     * A symlink pointing at a properly protected file must not be flagged. A symlink's own permissions are always
     * 0777 on Linux and cannot be changed, so checking the link instead of its target flags every symlink. This is
     * how Kubernetes exposes mounted secrets, and it was the false positive reported in issue #1891.
     */
    @Test
    public void symlinkToSecureFileIsNotFlagged() throws Exception {
        Path target = file("symlink-secure-target", "rw-------");
        Path link = Files.createSymbolicLink(tempDir.getRoot().toPath().resolve("symlink-secure"), target);

        // Guard the premise of this test rather than assuming the platform forces 0777 on the link itself.
        assumeTrue(
            "Symlink is not world accessible, so it would not trigger the check either way",
            Files.getPosixFilePermissions(link, LinkOption.NOFOLLOW_LINKS).contains(PosixFilePermission.OTHERS_READ)
        );

        assertThat(plugin.checkFilePermissions(link), equalTo(false));
    }

    /**
     * The converse of {@link #symlinkToSecureFileIsNotFlagged()}: a permissive target must still be reported even
     * when it is reached through a symlink, because that target is what OpenSearch ends up reading.
     */
    @Test
    public void symlinkToInsecureFileIsFlagged() throws Exception {
        Path target = file("symlink-insecure-target", "rw-r--r--");
        Path link = Files.createSymbolicLink(tempDir.getRoot().toPath().resolve("symlink-insecure"), target);

        assertThat(plugin.checkFilePermissions(link), equalTo(true));
    }

    @Test
    public void danglingSymlinkIsNotFlagged() throws Exception {
        Path link = Files.createSymbolicLink(
            tempDir.getRoot().toPath().resolve("dangling"),
            tempDir.getRoot().toPath().resolve("does-not-exist")
        );

        assertThat(plugin.checkFilePermissions(link), equalTo(false));
    }

    private Path file(final String name, final String permissions) throws Exception {
        Path path = tempDir.newFile(name).toPath();
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions));
        return path;
    }

    private Path directory(final String name, final String permissions) throws Exception {
        Path path = tempDir.newFolder(name).toPath();
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions));
        return path;
    }
}
