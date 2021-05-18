/*
 * Copyright 2015-2019 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package org.opensearch.security.auth.blocking;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class HeapBasedClientBlockRegistryTest {
    
    @Test
    public void simpleTest() throws Exception {   
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(50, 3, String.class);
       
        assertFalse(registry.isBlocked("a"));
        registry.block("a");
        assertTrue(registry.isBlocked("a"));
        
        registry.block("b");
        assertTrue(registry.isBlocked("a"));
        assertTrue(registry.isBlocked("b"));
        
        registry.block("c");
        assertTrue(registry.isBlocked("a"));
        assertTrue(registry.isBlocked("b"));
        assertTrue(registry.isBlocked("c"));
        
        registry.block("d");
        assertFalse(registry.isBlocked("a"));
        assertTrue(registry.isBlocked("b"));
        assertTrue(registry.isBlocked("c"));
        assertTrue(registry.isBlocked("d"));
    }
    
    @Test
    public void expiryTest() throws Exception {  
        HeapBasedClientBlockRegistry<String> registry = new HeapBasedClientBlockRegistry<>(50, 3, String.class);

        assertFalse(registry.isBlocked("a"));
        registry.block("a");
        assertTrue(registry.isBlocked("a"));
        Thread.sleep(55);
        assertFalse(registry.isBlocked("a"));
    }
}
