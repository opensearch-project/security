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

package org.opensearch.security.auth.limiting;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import org.opensearch.security.util.ratetracking.HeapBasedRateTracker;

public class HeapBasedRateTrackerTest {
    
    @Test
    public void simpleTest() throws Exception {   
        HeapBasedRateTracker<String> tracker = new HeapBasedRateTracker<>(100, 5, 100_000);
        
        assertFalse(tracker.track("a"));
        assertFalse(tracker.track("a"));
        assertFalse(tracker.track("a"));
        assertFalse(tracker.track("a"));
        assertTrue(tracker.track("a"));

    }
    
    @Test
    public void expiryTest() throws Exception {   
        HeapBasedRateTracker<String> tracker = new HeapBasedRateTracker<>(100, 5, 100_000);
        
        assertFalse(tracker.track("a"));
        assertFalse(tracker.track("a"));
        assertFalse(tracker.track("a"));
        assertFalse(tracker.track("a"));
        assertTrue(tracker.track("a"));

        assertFalse(tracker.track("b"));
        assertFalse(tracker.track("b"));
        assertFalse(tracker.track("b"));
        assertFalse(tracker.track("b"));
        assertTrue(tracker.track("b"));
        
        assertFalse(tracker.track("c"));    
        
        Thread.sleep(50);
        
        assertFalse(tracker.track("c"));   
        assertFalse(tracker.track("c"));      
        assertFalse(tracker.track("c"));   
        
        Thread.sleep(55); 
        
        assertFalse(tracker.track("c"));        
        assertTrue(tracker.track("c"));        

        assertFalse(tracker.track("a"));     
        
        Thread.sleep(55);
        assertFalse(tracker.track("c"));        
        assertFalse(tracker.track("c"));        
        assertTrue(tracker.track("c"));        

        
    }
    
    @Test
    public void maxTwoTriesTest() throws Exception {   
        HeapBasedRateTracker<String> tracker = new HeapBasedRateTracker<>(100, 2, 100_000);
        
        assertFalse(tracker.track("a"));
        assertTrue(tracker.track("a"));
        
        assertFalse(tracker.track("b"));
        Thread.sleep(50);
        assertTrue(tracker.track("b"));

        Thread.sleep(55);
        assertTrue(tracker.track("b"));

        Thread.sleep(105);
        assertFalse(tracker.track("b"));
        assertTrue(tracker.track("b"));

    }
}
