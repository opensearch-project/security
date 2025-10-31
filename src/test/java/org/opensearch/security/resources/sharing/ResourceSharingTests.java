/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources.sharing;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link org.opensearch.security.resources.sharing.ResourceSharing}.
 */
public class ResourceSharingTests {

    private CreatedBy mockCreatedBy(String username) {
        CreatedBy createdBy = mock(CreatedBy.class);
        when(createdBy.getUsername()).thenReturn(username);
        return createdBy;
    }

    private ShareWith mockShareWith(Map<String, Recipients> info) {
        ShareWith shareWith = mock(ShareWith.class);
        when(shareWith.getSharingInfo()).thenReturn(info);
        info.forEach((level, recipients) -> when(shareWith.atAccessLevel(eq(level))).thenReturn(recipients));
        return shareWith;
    }

    private Recipients mockRecipients(Map<Recipient, Set<String>> recipientsMap) {
        Recipients r = mock(Recipients.class);
        when(r.getRecipients()).thenReturn(recipientsMap);
        return r;
    }

    @Test
    public void share_initializesShareWithWhenNull() {
        CreatedBy createdBy = mockCreatedBy("alice");
        ResourceSharing rs = new ResourceSharing("res-1", createdBy, /*shareWith*/ null);

        Recipients target1 = mockRecipients(Map.of(Recipient.USERS, Set.of("bob")));
        Recipients target2 = mockRecipients(Map.of(Recipient.USERS, Set.of("not-bob")));
        rs.share("read", target1);
        rs.share("write", target2);

        ShareWith sw = rs.getShareWith();
        assertNotNull(sw);
        Map<String, Recipients> map = sw.getSharingInfo();
        assertNotNull(map);
        assertSame(target1, map.get("read"));
        assertSame(target2, map.get("write"));
    }

    @Test
    public void share_updatesExistingAccessLevelByMergingRecipients() {
        CreatedBy createdBy = mockCreatedBy("alice");

        Recipients existing = mock(Recipients.class);
        ShareWith sw = mock(ShareWith.class);
        when(sw.atAccessLevel("write")).thenReturn(existing);

        ResourceSharing rs = new ResourceSharing("res-1", createdBy, sw);

        Recipients newRecipients = mock(Recipients.class);
        rs.share("write", newRecipients);

        // should delegate merge to existing Recipients.share(target)
        verify(existing, times(1)).share(eq(newRecipients));
        verify(sw, never()).updateSharingInfo(anyString(), any());
    }

    @Test
    public void share_addsNewAccessLevelWhenAbsent() {
        CreatedBy createdBy = mockCreatedBy("alice");

        ShareWith sw = mock(ShareWith.class);
        when(sw.atAccessLevel("admin")).thenReturn(null);

        ShareWith updated = mock(ShareWith.class);
        when(sw.updateSharingInfo(eq("admin"), any(Recipients.class))).thenReturn(updated);

        ResourceSharing rs = new ResourceSharing("res-1", createdBy, sw);

        Recipients recipients = mock(Recipients.class);
        rs.share("admin", recipients);

        // should call updateSharingInfo and replace the shareWith instance
        verify(sw, times(1)).updateSharingInfo(eq("admin"), eq(recipients));
        assertSame(updated, rs.getShareWith());
    }

    @Test
    public void revoke_noopWhenShareWithIsNull() {
        CreatedBy createdBy = mockCreatedBy("alice");
        ResourceSharing rs = new ResourceSharing("res-1", createdBy, null);

        rs.revoke("read", mock(Recipients.class));
    }

    @Test
    public void revoke_logsWarningWhenAccessLevelMissing() {
        CreatedBy createdBy = mockCreatedBy("alice");
        ShareWith sw = mock(ShareWith.class);
        when(sw.atAccessLevel("read")).thenReturn(null);

        ResourceSharing rs = new ResourceSharing("res-1", createdBy, sw);
        rs.revoke("read", mock(Recipients.class));

        // nothing else to assert—just ensure no exceptions and no revoke() call
        verify(sw, times(1)).atAccessLevel("read");
    }

    @Test
    public void revoke_delegatesToRecipientsWhenPresent() {
        CreatedBy createdBy = mockCreatedBy("alice");
        Recipients existing = mock(Recipients.class);
        ShareWith sw = mock(ShareWith.class);
        when(sw.atAccessLevel("read")).thenReturn(existing);

        ResourceSharing rs = new ResourceSharing("res-1", createdBy, sw);
        Recipients target = mock(Recipients.class);

        rs.revoke("read", target);

        verify(existing, times(1)).revoke(eq(target));
    }

    @Test
    public void isCreatedBy_matchesUsername() {
        CreatedBy cb = mockCreatedBy("owner");
        ResourceSharing rs = new ResourceSharing("r", cb, null);

        assertTrue(rs.isCreatedBy("owner"));
        assertFalse(rs.isCreatedBy("other"));
    }

    @Test
    public void isSharedWithEveryone_delegatesToShareWith() {
        CreatedBy cb = mockCreatedBy("owner");
        ShareWith sw = mock(ShareWith.class);
        when(sw.isPublic()).thenReturn(true);

        ResourceSharing rs = new ResourceSharing("r", cb, sw);
        assertTrue(rs.isSharedWithEveryone());

        when(sw.isPublic()).thenReturn(false);
        assertFalse(rs.isSharedWithEveryone());

        ResourceSharing rs2 = new ResourceSharing("r", cb, null);
        assertFalse(rs2.isSharedWithEveryone());
    }

    @Test
    public void isSharedWithEntity_handlesNullsAndDelegates() {
        CreatedBy cb = mockCreatedBy("owner");

        // Case 1: shareWith == null
        ResourceSharing rs1 = new ResourceSharing("r", cb, null);
        assertFalse(rs1.isSharedWithEntity(Recipient.USERS, Set.of("u1"), "read"));

        // Case 2: access level missing
        ShareWith sw = mock(ShareWith.class);
        when(sw.atAccessLevel("read")).thenReturn(null);
        ResourceSharing rs2 = new ResourceSharing("r", cb, sw);
        assertFalse(rs2.isSharedWithEntity(Recipient.USERS, Set.of("u1"), "read"));

        // Case 3: access level present -> delegate to Recipients.isSharedWithAny()
        Recipients rec = mock(Recipients.class);
        when(sw.atAccessLevel("read")).thenReturn(rec);
        when(rec.isSharedWithAny(eq(Recipient.USERS), eq(Set.of("u1")))).thenReturn(true);

        assertTrue(rs2.isSharedWithEntity(Recipient.USERS, Set.of("u1"), "read"));
        verify(rec, times(1)).isSharedWithAny(eq(Recipient.USERS), eq(Set.of("u1")));
    }

    @Test
    public void fetchAccessLevels_returnsLevelsWithWildcardOrIntersection() {
        CreatedBy cb = mockCreatedBy("o");

        // level:read has users {"u1", "*"} -> wildcard = match
        Recipients rRead = mockRecipients(Map.of(Recipient.USERS, new HashSet<>(Set.of("u1", "*"))));
        // level:write has roles {"roleA"} -> no match for {"roleB"} unless overlap
        Recipients rWrite = mockRecipients(Map.of(Recipient.ROLES, new HashSet<>(Set.of("roleA"))));
        // level:admin has backend {"br1","br2"} -> intersection with {"br2"} = match
        Recipients rAdmin = mockRecipients(Map.of(Recipient.BACKEND_ROLES, new HashSet<>(Set.of("br1", "br2"))));

        Map<String, Recipients> map = new HashMap<>();
        map.put("read", rRead);
        map.put("write", rWrite);
        map.put("admin", rAdmin);

        ShareWith sw = mockShareWith(map);

        ResourceSharing rs = new ResourceSharing("r", cb, sw);

        // users, looking for anything in {"any"} -> wildcard on read makes it match
        Set<String> levelsUsers = rs.fetchAccessLevels(Recipient.USERS, Set.of("any"));
        assertEquals(Set.of("read"), levelsUsers);

        // roles, looking for {"roleB"} -> no match; {"roleA"} -> match write
        assertTrue(rs.fetchAccessLevels(Recipient.ROLES, Set.of("roleB")).isEmpty());
        assertEquals(Set.of("write"), rs.fetchAccessLevels(Recipient.ROLES, Set.of("roleA")));

        // backend roles, looking for {"br2"} -> match admin
        assertEquals(Set.of("admin"), rs.fetchAccessLevels(Recipient.BACKEND_ROLES, Set.of("br2")));
    }

    @Test
    public void fetchAccessLevels_returnsEmptyWhenShareWithIsNull() {
        ResourceSharing rs = new ResourceSharing("r", mockCreatedBy("o"), null);
        assertTrue(rs.fetchAccessLevels(Recipient.USERS, Set.of("x")).isEmpty());
    }

    @Test
    public void getAllPrincipals_includesCreatorAndAllRecipientsAcrossLevels() {
        CreatedBy cb = mockCreatedBy("owner");

        Recipients read = mockRecipients(Map.of(Recipient.USERS, Set.of("u1", "u2"), Recipient.ROLES, Set.of("r1")));
        Recipients write = mockRecipients(Map.of(Recipient.BACKEND_ROLES, Set.of("br1"), Recipient.USERS, Set.of("u3")));

        Map<String, Recipients> info = new HashMap<>();
        info.put("read", read);
        info.put("write", write);

        ShareWith sw = mockShareWith(info);

        ResourceSharing rs = new ResourceSharing("r", cb, sw);
        List<String> principals = rs.getAllPrincipals();

        assertTrue(principals.contains("user:owner"));
        assertTrue(principals.contains("user:u1"));
        assertTrue(principals.contains("user:u2"));
        assertTrue(principals.contains("user:u3"));
        assertTrue(principals.contains("role:r1"));
        assertTrue(principals.contains("backend:br1"));

        // sanity: no duplicates
        assertEquals(new HashSet<>(principals).size(), principals.size());
    }

    @Test
    public void getAllPrincipals_handlesNullShareWith() {
        ResourceSharing rs = new ResourceSharing("r", mockCreatedBy("owner"), null);
        List<String> principals = rs.getAllPrincipals();
        assertEquals(1, principals.size());
        assertEquals("user:owner", principals.get(0));
    }
}
