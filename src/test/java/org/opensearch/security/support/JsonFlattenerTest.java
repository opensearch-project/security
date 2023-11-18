/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

public class JsonFlattenerTest {
    @Test
    public void testFlattenAsMapBasic() {
        Map<String, Object> flattenedMap1 = JsonFlattener.flattenAsMap("{\"key\": {\"nested\": 1}, \"another.key\": [\"one\", \"two\"] }");
        assertThat(flattenedMap1.keySet(), containsInAnyOrder("key.nested", "key", "another.key[0]", "another.key[1]", "another.key"));
        assertThat(
            flattenedMap1.values(),
            containsInAnyOrder(1, "one", "two", Arrays.asList("one", "two"), Collections.singletonMap("nested", 1))
        );
        Map<String, Object> flattenedMap2 = JsonFlattener.flattenAsMap("{\"a\":1, \"b\":2, \"cn\":{\"c\":[3,4]}}");
        assertThat(flattenedMap2.keySet(), containsInAnyOrder("a", "b", "cn.c[0]", "cn.c[1]", "cn.c", "cn"));
        assertThat(
            flattenedMap2.values(),
            containsInAnyOrder(1, 2, 3, 4, Arrays.asList(3, 4), Collections.singletonMap("c", Arrays.asList(3, 4)))
        );
        Map<String, Object> flattenedMap3 = JsonFlattener.flattenAsMap("{}");
        assertThat(flattenedMap3.keySet(), is(empty()));
        assertThat(flattenedMap3.values(), is(empty()));
    }

    @Test
    public void testFlattenAsMapComplex() {
        Map<String, Object> flattenedMap1 = JsonFlattener.flattenAsMap("{\n" + //
            "  \"a\": {\n" + //
            "    \"b\": 1,\n" + //
            "    \"c\": null,\n" + //
            "    \"d\": [\n" + //
            "      false,\n" + //
            "      true\n" + //
            "    ]\n" + //
            "  },\n" + //
            "  \"e\": \"f\",\n" + //
            "  \"g\": 2.30\n" + //
            "}");
        assertThat(flattenedMap1.keySet(), containsInAnyOrder("a.b", "a.c", "a.d[0]", "a.d[1]", "a.d", "a", "e", "g"));
        HashMap<String, Object> subMap1 = new HashMap<>();
        subMap1.put("b", 1);
        subMap1.put("c", null);
        subMap1.put("d", Arrays.asList(false, true));
        assertThat(flattenedMap1.values(), containsInAnyOrder(1, null, false, true, Arrays.asList(false, true), subMap1, "f", 2.3));
        Map<String, Object> flattenedMap2 = JsonFlattener.flattenAsMap(
            "{\"a\":{\"b\":1,\"c\":null,\"d\":[false,{\"i\":{\"j\":[false,true,\"xy\"]}}]},\"e\":\"f\",\"g\":2.3,\"z\":[]}"
        );
        assertThat(
            flattenedMap2.keySet(),
            containsInAnyOrder(
                "a.b",
                "a.c",
                "a.d[0]",
                "a.d[1].i.j[0]",
                "a.d[1].i.j[1]",
                "a.d[1].i.j[2]",
                "a.d[1].i.j",
                "a.d[1].i",
                "a.d[1]",
                "a.d",
                "a",
                "e",
                "g",
                "z"
            )
        );
        subMap1 = new HashMap<>();
        subMap1.put("b", 1);
        subMap1.put("c", null);
        subMap1.put(
            "d",
            Arrays.asList(false, Collections.singletonMap("i", Collections.singletonMap("j", Arrays.asList(false, true, "xy"))))
        );
        assertThat(
            flattenedMap2.values(),
            containsInAnyOrder(
                1,
                null,
                false,
                false,
                true,
                "xy",
                Arrays.asList(false, true, "xy"),
                Collections.singletonMap("j", Arrays.asList(false, true, "xy")),
                Collections.singletonMap("i", Collections.singletonMap("j", Arrays.asList(false, true, "xy"))),
                Arrays.asList(false, Collections.singletonMap("i", Collections.singletonMap("j", Arrays.asList(false, true, "xy")))),
                subMap1,
                "f",
                2.3,
                Collections.emptyList()
            )
        );
        Map<String, Object> flattenedMap3 = JsonFlattener.flattenAsMap("{\n" + //
            "\t\"glossary\": {\n" + //
            "\t\t\"title\": \"example glossary\",\n" + //
            "\t\t\"GlossDiv\": {\n" + //
            "\t\t\t\"title\": \"S\",\n" + //
            "\t\t\t\"GlossList\": {\n" + //
            "\t\t\t\t\"GlossEntry\": {\n" + //
            "\t\t\t\t\t\"ID\": \"SGML\",\n" + //
            "\t\t\t\t\t\"SortAs\": \"SGML\",\n" + //
            "\t\t\t\t\t\"GlossTerm\": \"Standard Generalized Markup Language\",\n" + //
            "\t\t\t\t\t\"Acronym\": \"SGML\",\n" + //
            "\t\t\t\t\t\"Abbrev\": \"ISO 8879:1986\",\n" + //
            "\t\t\t\t\t\"GlossDef\": {\n" + //
            "\t\t\t\t\t\t\"para\": \"A meta-markup language, used to create markup languages such as DocBook.\",\n" + //
            "\t\t\t\t\t\t\"GlossSeeAlso\": [\n" + //
            "\t\t\t\t\t\t\t\"GML\",\n" + //
            "\t\t\t\t\t\t\t\"XML\"\n" + //
            "\t\t\t\t\t\t]\n" + //
            "\t\t\t\t\t},\n" + //
            "\t\t\t\t\t\"GlossSee\": \"markup\"\n" + //
            "\t\t\t\t}\n" + //
            "\t\t\t}\n" + //
            "\t\t}\n" + //
            "\t}\n" + //
            "}");
        assertThat(
            flattenedMap3.keySet(),
            containsInAnyOrder(
                "glossary.title",
                "glossary.GlossDiv.title",
                "glossary.GlossDiv.GlossList.GlossEntry.ID",
                "glossary.GlossDiv.GlossList.GlossEntry.SortAs",
                "glossary.GlossDiv.GlossList.GlossEntry.GlossTerm",
                "glossary.GlossDiv.GlossList.GlossEntry.Acronym",
                "glossary.GlossDiv.GlossList.GlossEntry.Abbrev",
                "glossary.GlossDiv.GlossList.GlossEntry.GlossDef.para",
                "glossary.GlossDiv.GlossList.GlossEntry.GlossDef.GlossSeeAlso[0]",
                "glossary.GlossDiv.GlossList.GlossEntry.GlossDef.GlossSeeAlso[1]",
                "glossary.GlossDiv.GlossList.GlossEntry.GlossDef.GlossSeeAlso",
                "glossary.GlossDiv.GlossList.GlossEntry.GlossDef",
                "glossary.GlossDiv.GlossList.GlossEntry.GlossSee",
                "glossary.GlossDiv.GlossList.GlossEntry",
                "glossary.GlossDiv.GlossList",
                "glossary.GlossDiv",
                "glossary"
            )
        );
        assertThat(
            flattenedMap3.values(),
            containsInAnyOrder(
                "example glossary",
                "S",
                "SGML",
                "SGML",
                "Standard Generalized Markup Language",
                "SGML",
                "ISO 8879:1986",
                "A meta-markup language, used to create markup languages such as DocBook.",
                "GML",
                "XML",
                Arrays.asList("GML", "XML"),
                Map.of(
                    "para",
                    "A meta-markup language, used to create markup languages such as DocBook.",
                    "GlossSeeAlso",
                    Arrays.asList("GML", "XML")
                ),
                "markup",
                Map.of(
                    "ID",
                    "SGML",
                    "SortAs",
                    "SGML",
                    "GlossTerm",
                    "Standard Generalized Markup Language",
                    "Acronym",
                    "SGML",
                    "Abbrev",
                    "ISO 8879:1986",
                    "GlossDef",
                    Map.of(
                        "para",
                        "A meta-markup language, used to create markup languages such as DocBook.",
                        "GlossSeeAlso",
                        Arrays.asList("GML", "XML")
                    ),
                    "GlossSee",
                    "markup"
                ),
                Map.of(
                    "GlossEntry",
                    Map.of(
                        "ID",
                        "SGML",
                        "SortAs",
                        "SGML",
                        "GlossTerm",
                        "Standard Generalized Markup Language",
                        "Acronym",
                        "SGML",
                        "Abbrev",
                        "ISO 8879:1986",
                        "GlossDef",
                        Map.of(
                            "para",
                            "A meta-markup language, used to create markup languages such as DocBook.",
                            "GlossSeeAlso",
                            Arrays.asList("GML", "XML")
                        ),
                        "GlossSee",
                        "markup"
                    )
                ),
                Map.of(
                    "title",
                    "S",
                    "GlossList",
                    Map.of(
                        "GlossEntry",
                        Map.of(
                            "ID",
                            "SGML",
                            "SortAs",
                            "SGML",
                            "GlossTerm",
                            "Standard Generalized Markup Language",
                            "Acronym",
                            "SGML",
                            "Abbrev",
                            "ISO 8879:1986",
                            "GlossDef",
                            Map.of(
                                "para",
                                "A meta-markup language, used to create markup languages such as DocBook.",
                                "GlossSeeAlso",
                                Arrays.asList("GML", "XML")
                            ),
                            "GlossSee",
                            "markup"
                        )
                    )
                ),
                Map.of(
                    "title",
                    "example glossary",
                    "GlossDiv",
                    Map.of(
                        "title",
                        "S",
                        "GlossList",
                        Map.of(
                            "GlossEntry",
                            Map.of(
                                "ID",
                                "SGML",
                                "SortAs",
                                "SGML",
                                "GlossTerm",
                                "Standard Generalized Markup Language",
                                "Acronym",
                                "SGML",
                                "Abbrev",
                                "ISO 8879:1986",
                                "GlossDef",
                                Map.of(
                                    "para",
                                    "A meta-markup language, used to create markup languages such as DocBook.",
                                    "GlossSeeAlso",
                                    Arrays.asList("GML", "XML")
                                ),
                                "GlossSee",
                                "markup"
                            )
                        )
                    )
                )
            )
        );
        Map<String, Object> flattenedMap4 = JsonFlattener.flattenAsMap("{\n" + //
            "\t\"arrayOfObjects\": [\n" + //
            "\t\ttrue,\n" + //
            "\t\t{\n" + //
            "\t\t\t\"x\": 1,\n" + //
            "\t\t\t\"y\": 2,\n" + //
            "\t\t\t\"z\": [\n" + //
            "\t\t\t\t3,\n" + //
            "\t\t\t\t4,\n" + //
            "\t\t\t\t5\n" + //
            "\t\t\t]\n" + //
            "\t\t},\n" + //
            "\t\t[\n" + //
            "\t\t\t6,\n" + //
            "\t\t\t7,\n" + //
            "\t\t\t8\n" + //
            "\t\t],\n" + //
            "\t\t[\n" + //
            "\t\t\t[\n" + //
            "\t\t\t\t9,\n" + //
            "\t\t\t\t10\n" + //
            "\t\t\t],\n" + //
            "\t\t\t11,\n" + //
            "\t\t\t12\n" + //
            "\t\t],\n" + //
            "\t\tfalse\n" + //
            "\t],\n" + //
            "\t\"boolean\": true,\n" + //
            "\t\"color\": \"#82b92c\",\n" + //
            "\t\"null\": null,\n" + //
            "\t\"number\": 123,\n" + //
            "\t\"object\": {\n" + //
            "\t\t\"a\": \"b\",\n" + //
            "\t\t\"c\": \"d\",\n" + //
            "\t\t\"e\": \"f\"\n" + //
            "\t},\n" + //
            "\t\"string\": \"Hello World\"\n" + //
            "}");
        assertThat(
            flattenedMap4.keySet(),
            containsInAnyOrder(
                "arrayOfObjects[0]",
                "arrayOfObjects[1].x",
                "arrayOfObjects[1].y",
                "arrayOfObjects[1].z[0]",
                "arrayOfObjects[1].z[1]",
                "arrayOfObjects[1].z[2]",
                "arrayOfObjects[1].z",
                "arrayOfObjects[1]",
                "arrayOfObjects[2][0]",
                "arrayOfObjects[2][1]",
                "arrayOfObjects[2][2]",
                "arrayOfObjects[2]",
                "arrayOfObjects[3][0][0]",
                "arrayOfObjects[3][0][1]",
                "arrayOfObjects[3][0]",
                "arrayOfObjects[3][1]",
                "arrayOfObjects[3][2]",
                "arrayOfObjects[3]",
                "arrayOfObjects[4]",
                "arrayOfObjects",
                "boolean",
                "color",
                "null",
                "number",
                "object.a",
                "object.c",
                "object.e",
                "object",
                "string"
            )
        );
        assertThat(
            flattenedMap4.values(),
            containsInAnyOrder(
                true,
                1,
                2,
                3,
                4,
                5,
                Arrays.asList(3, 4, 5),
                Map.of("x", 1, "y", 2, "z", Arrays.asList(3, 4, 5)),
                6,
                7,
                8,
                Arrays.asList(6, 7, 8),
                9,
                10,
                Arrays.asList(9, 10),
                11,
                12,
                Arrays.asList(Arrays.asList(9, 10), 11, 12),
                false,
                Arrays.asList(
                    true,
                    Map.of("x", 1, "y", 2, "z", Arrays.asList(3, 4, 5)),
                    Arrays.asList(6, 7, 8),
                    Arrays.asList(Arrays.asList(9, 10), 11, 12),
                    false
                ),
                true,
                "#82b92c",
                null,
                123,
                "b",
                "d",
                "f",
                Map.of("a", "b", "c", "d", "e", "f"),
                "Hello World"
            )
        );
    }
}
