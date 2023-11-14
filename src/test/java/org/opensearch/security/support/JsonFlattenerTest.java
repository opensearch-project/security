package org.opensearch.security.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;

public class JsonFlattenerTest {
    @Test
    public void testFlattenAsMapBasic() {
        Map<String, Object> flattenedMap = JsonFlattener.flattenAsMap("{\"key\": {\"nested\": 1}, \"another.key\": [\"one\", \"two\"] }");
        assertThat(flattenedMap.keySet(), containsInAnyOrder("key.nested", "key", "another.key[0]", "another.key[1]", "another.key"));
        assertThat(
            flattenedMap.values(),
            containsInAnyOrder(1, "one", "two", Arrays.asList("one", "two"), Collections.singletonMap("nested", 1))
        );
    }
}
