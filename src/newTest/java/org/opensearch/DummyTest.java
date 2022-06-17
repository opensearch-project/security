package org.opensearch;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DummyTest {

    @Test
    public void test() {
        int a = 1, b = 2, expectedSum = 3;


        int actualSum = a + b;

        assertEquals(expectedSum, actualSum);
    }

}
