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

package org.opensearch.security.securityconf;

import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;

import java.util.List;
import java.util.Set;

public interface IndexPattern {
    void addFlsFields(List<String> flsFields);

    void addMaskedFields(List<String> maskedFields);

    void setDlsQuery(String dls);

    void addTypePerms(TypePerm typePerm);

    void addPerm(Set<String> strings);

    boolean hasDlsQuery();

    boolean hasFlsFields();

    boolean hasMaskedFields();

    String getDlsQuery(User user);

    String getUnresolvedIndexPattern(User user);

    Set<String> getPermsAsCollection();

    Set<String> concreteIndexNames(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<String> getFls();

    Set<String> getMaskedFields();

    Set<String> attemptResolveIndexNames(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<String> getResolvedIndexPattern(User user, IndexNameExpressionResolver resolver, ClusterService cs);

    Set<TypePerm> getTypePerms();

    WildcardMatcher getPerms();

    WildcardMatcher getNonWildCardPerms();
}
