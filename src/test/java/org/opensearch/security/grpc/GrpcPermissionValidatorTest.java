package org.opensearch.security.grpc;

import org.junit.Test;
import org.opensearch.security.user.User;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;

import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class GrpcPermissionValidatorTest {

    @Test
    public void testValidSearchRole() {
        PrivilegesEvaluator mockEvaluator = mock(PrivilegesEvaluator.class);
        PrivilegesEvaluationContext mockContext = mock(PrivilegesEvaluationContext.class);
        PrivilegesEvaluatorResponse allowedResponse = mock(PrivilegesEvaluatorResponse.class);
        
        when(mockEvaluator.createContext(any(User.class), anyString())).thenReturn(mockContext);
        when(mockEvaluator.evaluate(mockContext)).thenReturn(allowedResponse);
        when(allowedResponse.isAllowed()).thenReturn(true);
        
        GrpcPermissionValidator validator = new GrpcPermissionValidator(mockEvaluator);
        User user = new User("testuser");
        user = user.withRoles(Set.of("grpc_search_role"));
        
        GrpcPermissionValidator.ValidationResponse response = validator.validatePermissions(user, "org.opensearch.protobufs.services.SearchService");
        assertTrue(response.hasPermission());
        assertNull(response.error());
        
        verify(mockEvaluator).createContext(user, "grpc:search");
        verify(mockEvaluator).evaluate(mockContext);
    }

    @Test
    public void testInvalidRole() {
        PrivilegesEvaluator mockEvaluator = mock(PrivilegesEvaluator.class);
        PrivilegesEvaluationContext mockContext = mock(PrivilegesEvaluationContext.class);
        PrivilegesEvaluatorResponse deniedResponse = mock(PrivilegesEvaluatorResponse.class);
        
        when(mockEvaluator.createContext(any(User.class), anyString())).thenReturn(mockContext);
        when(mockEvaluator.evaluate(mockContext)).thenReturn(deniedResponse);
        when(deniedResponse.isAllowed()).thenReturn(false);
        
        GrpcPermissionValidator validator = new GrpcPermissionValidator(mockEvaluator);
        User user = new User("testuser");
        user = user.withRoles(Set.of("some_other_role"));
        
        GrpcPermissionValidator.ValidationResponse response = validator.validatePermissions(user, "org.opensearch.protobufs.services.SearchService");
        assertFalse(response.hasPermission());
        assertTrue(response.error().contains("gRPC access denied"));
        assertTrue(response.error().contains("grpc:search"));
    }

    @Test
    public void testUnknownService() {
        PrivilegesEvaluator mockEvaluator = mock(PrivilegesEvaluator.class);
        GrpcPermissionValidator validator = new GrpcPermissionValidator(mockEvaluator);
        User user = new User("testuser");
        user = user.withRoles(Set.of("admin"));
        
        GrpcPermissionValidator.ValidationResponse response = validator.validatePermissions(user, "unknown.service");
        assertFalse(response.hasPermission());
        assertTrue(response.error().contains("Unknown gRPC service"));
        
        // Should not call evaluator for unknown service
        verify(mockEvaluator, never()).createContext(any(), any());
        verify(mockEvaluator, never()).evaluate(any());
    }

    @Test
    public void testIndexService() {
        PrivilegesEvaluator mockEvaluator = mock(PrivilegesEvaluator.class);
        PrivilegesEvaluationContext mockContext = mock(PrivilegesEvaluationContext.class);
        PrivilegesEvaluatorResponse allowedResponse = mock(PrivilegesEvaluatorResponse.class);
        
        when(mockEvaluator.createContext(any(User.class), anyString())).thenReturn(mockContext);
        when(mockEvaluator.evaluate(mockContext)).thenReturn(allowedResponse);
        when(allowedResponse.isAllowed()).thenReturn(true);
        
        GrpcPermissionValidator validator = new GrpcPermissionValidator(mockEvaluator);
        User user = new User("testuser");
        user = user.withRoles(Set.of("grpc_index_role"));
        
        GrpcPermissionValidator.ValidationResponse response = validator.validatePermissions(user, "org.opensearch.protobufs.services.IndexService");
        assertTrue(response.hasPermission());
        
        // Verify the correct action was checked
        verify(mockEvaluator).createContext(user, "grpc:index");
        verify(mockEvaluator).evaluate(mockContext);
    }
}
