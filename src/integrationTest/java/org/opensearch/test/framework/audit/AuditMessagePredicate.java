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
import static org.opensearch.security.auditlog.impl.AuditMessage.REST_REQUEST_PARAMS;
import static org.opensearch.security.auditlog.impl.AuditMessage.REST_REQUEST_PATH;

public class AuditMessagePredicate implements Predicate<AuditMessage> {

    private final AuditCategory category;
    private final Origin requestLayer;
    private final String restRequestPath;
    private final Map<String, String> restParams;
    private final String initiatingUser;
    private final Method requestMethod;
    private final String transportRequestType;
    private final String effectiveUser;
    private final String index;
    private final String privilege;

    private AuditMessagePredicate(
        AuditCategory category,
        Origin requestLayer,
        String restRequestPath,
        Map<String, String> restParams,
        String initiatingUser,
        Method requestMethod,
        String transportRequestType,
        String effectiveUser,
        String index,
        String privilege
    ) {
        this.category = category;
        this.requestLayer = requestLayer;
        this.restRequestPath = restRequestPath;
        this.restParams = restParams;
        this.initiatingUser = initiatingUser;
        this.requestMethod = requestMethod;
        this.transportRequestType = transportRequestType;
        this.effectiveUser = effectiveUser;
        this.index = index;
        this.privilege = privilege;
    }

    private AuditMessagePredicate(AuditCategory category) {
        this(category, null, null, null, null, null, null, null, null, null);
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

    public static AuditMessagePredicate privilegePredicateTransportLayer(
        AuditCategory category,
        User user,
        String requestType,
        String privilege
    ) {
        return auditPredicate(category).withLayer(Origin.TRANSPORT)
            .withEffectiveUser(user)
            .withPrivilege(privilege)
            .withTransportRequestType(requestType);
    }

    public static AuditMessagePredicate privilegePredicateRESTLayer(AuditCategory category, User user, Method method, String endpoint) {
        return auditPredicate(category).withLayer(Origin.REST).withEffectiveUser(user).withRestRequest(method, endpoint);
    }

    public static AuditMessagePredicate userAuthenticatedPredicate(User user, Method method, String endpoint) {
        return userAuthenticated(user).withLayer(Origin.REST).withRestRequest(method, endpoint).withInitiatingUser(user);
    }

    public AuditMessagePredicate withLayer(Origin layer) {
        return new AuditMessagePredicate(
            category,
            layer,
            restRequestPath,
            restParams,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index,
            privilege
        );
    }

    public AuditMessagePredicate withRequestPath(String path) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            path,
            restParams,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index,
            privilege
        );
    }

    public AuditMessagePredicate withRestParams(Map<String, String> params) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            params,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index,
            privilege
        );
    }

    public AuditMessagePredicate withInitiatingUser(String user) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            restParams,
            user,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index,
            privilege
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
            restParams,
            initiatingUser,
            method,
            transportRequestType,
            effectiveUser,
            index,
            privilege
        );
    }

    public AuditMessagePredicate withTransportRequestType(String type) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            restParams,
            initiatingUser,
            requestMethod,
            type,
            effectiveUser,
            index,
            privilege
        );
    }

    public AuditMessagePredicate withEffectiveUser(String user) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            restParams,
            initiatingUser,
            requestMethod,
            transportRequestType,
            user,
            index,
            privilege
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
            restParams,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            indexName,
            privilege
        );
    }

    public AuditMessagePredicate withPrivilege(String privilegeAction) {
        return new AuditMessagePredicate(
            category,
            requestLayer,
            restRequestPath,
            restParams,
            initiatingUser,
            requestMethod,
            transportRequestType,
            effectiveUser,
            index,
            privilegeAction
        );
    }

    @Override
    public boolean test(AuditMessage auditMessage) {
        List<Predicate<AuditMessage>> predicates = new ArrayList<>();
        predicates.add(audit -> Objects.isNull(category) || category.equals(audit.getCategory()));
        predicates.add(audit -> Objects.isNull(requestLayer) || requestLayer.equals(audit.getAsMap().get(REQUEST_LAYER)));
        predicates.add(audit -> Objects.isNull(restRequestPath) || restRequestPath.equals(audit.getAsMap().get(REST_REQUEST_PATH)));
        predicates.add(audit -> Objects.isNull(restParams) || restParams.equals(auditMessage.getAsMap().get(REST_REQUEST_PARAMS)));
        predicates.add(audit -> Objects.isNull(initiatingUser) || initiatingUser.equals(audit.getInitiatingUser()));
        predicates.add(audit -> Objects.isNull(requestMethod) || requestMethod.equals(audit.getRequestMethod()));
        predicates.add(audit -> Objects.isNull(transportRequestType) || transportRequestType.equals(audit.getRequestType()));
        predicates.add(audit -> Objects.isNull(effectiveUser) || effectiveUser.equals(audit.getEffectiveUser()));
        predicates.add(audit -> Objects.isNull(index) || containIndex(audit, index));
        predicates.add(audit -> Objects.isNull(privilege) || privilege.equals(audit.getPrivilege()));
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
