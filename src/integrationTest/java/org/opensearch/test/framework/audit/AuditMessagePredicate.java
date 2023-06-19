/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.audit;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.test.framework.TestSecurityConfig.User;

import static org.opensearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditCategory.MISSING_PRIVILEGES;
import static org.opensearch.security.auditlog.impl.AuditMessage.REQUEST_LAYER;
import static org.opensearch.security.auditlog.impl.AuditMessage.RESOLVED_INDICES;
import static org.opensearch.security.auditlog.impl.AuditMessage.REST_REQUEST_PATH;

public class AuditMessagePredicate implements Predicate<AuditMessage> {

    private final AuditCategory category;
    private final Origin requestLayer;
    private final String restRequestPath;
    private final String initiatingUser;
    private final Method requestMethod;
    private final String transportRequestType;
    private final String effectiveUser;
    private final String index;

    private AuditMessagePredicate(
        AuditCategory category,
        Origin requestLayer,
        String restRequestPath,
        String initiatingUser,
        Method requestMethod,
        String transportRequestType,
        String effectiveUser,
        String index
    ) {
        this.category = category;
        this.requestLayer = requestLayer;
        this.restRequestPath = restRequestPath;
        this.initiatingUser = initiatingUser;
        this.requestMethod = requestMethod;
        this.transportRequestType = transportRequestType;
        this.effectiveUser = effectiveUser;
        this.index = index;
    }

    private AuditMessagePredicate(AuditCategory category) {
        this(category, null, null, null, null, null, null, null);
    }

    public static AuditMessagePredicate auditPredicate(AuditCategory category) {
        return new AuditMessagePredicate(category);
    }

    public static AuditMessagePredicate userAuthenticated(User user) {
        return auditPredicate(AUTHENTICATED).withInitiatingUser(user);
    }

    public static AuditMessagePredicate grantedPrivilege(User user, String requestType) {
        return auditPredicate(GRANTED_PRIVILEGES).withLayer(Origin.TRANSPORT).withEffectiveUser(user).withTransportRequestType(requestType);
    }

    public static AuditMessagePredicate missingPrivilege(User user, String requestType) {
        return auditPredicate(MISSING_PRIVILEGES).withLayer(Origin.TRANSPORT).withEffectiveUser(user).withTransportRequestType(requestType);
    }

    public AuditMessagePredicate withLayer(Origin layer) {
        return new AuditMessagePredicate(
            category,
            layer,
            restRequestPath,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index
        );
    }

    public AuditMessagePredicate withRequestPath(String path) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            path,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index
        );
    }

    public AuditMessagePredicate withInitiatingUser(String user) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            user,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index
        );
    }

    public AuditMessagePredicate withInitiatingUser(User user) {
        return withInitiatingUser(user.getName());
    }

    public AuditMessagePredicate withRestMethod(Method method) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            initiatingUser,
            method,
            transportRequestType,
            effectiveUser,
            index
        );
    }

    public AuditMessagePredicate withTransportRequestType(String type) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            initiatingUser,
            requestMethod,
            type,
            effectiveUser,
            index
        );
    }

    public AuditMessagePredicate withEffectiveUser(String user) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            initiatingUser,
            requestMethod,
            transportRequestType,
            user,
            index
        );
    }

    public AuditMessagePredicate withEffectiveUser(User user) {
        return withEffectiveUser(user.getName());
    }

    public AuditMessagePredicate withRestRequest(Method method, String path) {
        return this.withLayer(Origin.REST).withRestMethod(method).withRequestPath(path);
    }

    public AuditMessagePredicate withIndex(String indexName) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            indexName
        );
    }

    @Override
    public boolean test(AuditMessage auditMessage) {
        List<Predicate<AuditMessage>> predicates = new ArrayList<>();
        predicates.add(audit -> Objects.isNull(category) || category.equals(audit.getCategory()));
        predicates.add(audit -> Objects.isNull(requestLayer) || requestLayer.equals(audit.getAsMap().get(REQUEST_LAYER)));
        predicates.add(audit -> Objects.isNull(restRequestPath) || restRequestPath.equals(audit.getAsMap().get(REST_REQUEST_PATH)));
        predicates.add(audit -> Objects.isNull(initiatingUser) || initiatingUser.equals(audit.getInitiatingUser()));
        predicates.add(audit -> Objects.isNull(requestMethod) || requestMethod.equals(audit.getRequestMethod()));
        predicates.add(audit -> Objects.isNull(transportRequestType) || transportRequestType.equals(audit.getRequestType()));
        predicates.add(audit -> Objects.isNull(effectiveUser) || effectiveUser.equals(audit.getEffectiveUser()));
        predicates.add(audit -> Objects.isNull(index) || containIndex(audit, index));
        return predicates.stream().reduce(Predicate::and).orElseThrow().test(auditMessage);
    }

    private boolean containIndex(AuditMessage auditMessage, String indexName) {
        Map<String, Object> audit = auditMessage.getAsMap();
        return Optional.ofNullable(audit.get(RESOLVED_INDICES))
            .filter(String[].class::isInstance)
            .map(String[].class::cast)
            .stream()
            .flatMap(Arrays::stream)
            .collect(Collectors.toSet())
            .contains(indexName);
    }

    @Override
    public String toString() {
        return "AuditMessagePredicate{"
            + "category="
            + category
            + ", requestLayer="
            + requestLayer
            + ", restRequestPath='"
            + restRequestPath
            + '\''
            + ", requestInitiatingUser='"
            + initiatingUser
            + '\''
            + ", requestMethod="
            + requestMethod
            + ", transportRequestType='"
            + transportRequestType
            + '\''
            + '}';
    }
}
