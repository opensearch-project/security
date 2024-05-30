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
package org.opensearch.security.privileges;

import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.google.common.collect.ImmutableSet;

/**
 * A specialized data structure which represents a matrix of checkmarks. During construction, you can specify its rows
 * and columns. Initially, all cells of the matrix are unchecked. You can use the check() method to set particular
 * cells to checked(). There are various methods to query the state of the whole matrix, of columns and rows.
 *
 * The state of the matrix can be visualized with the toTableString() method:
 *
 * <pre>
 *          | indices:data/read/search |
 * index_a11| ok                       |
 * index_a12| MISSING                  |
 * index_a13| MISSING                  |
 * index_a14| MISSING                  |
 * </pre>
 *
 * TODO: This is for now just a minimalistic, inefficient and non-production-ready implementation. A better replacement is
 * necessary.
 */
public class CheckTable<R, C> {
    private HashSet<String> checked = new HashSet<>();
    private Set<R> rows;
    private Set<C> columns;
    private int size;

    public boolean check(R row, C column) {
        if (!checked.contains(row + "::" + column)) {
            checked.add(row + "::" + column);
        }

        return isComplete();
    }

    public boolean isChecked(R row, C column) {
        return checked.contains(row + "::" + column);
    }

    public boolean isComplete() {
        return size == checked.size();
    }

    public boolean isRowComplete(R row) {
        for (C column : this.columns) {
            boolean checked = this.isChecked(row, column);

            if (!checked) {
                return false;
            }
        }

        return true;
    }

    public boolean isColumnComplete(C column) {
        for (R row : this.rows) {
            boolean checked = this.isChecked(row, column);

            if (!checked) {
                return false;
            }
        }

        return true;
    }

    public ImmutableSet<R> getCompleteRows() {
        if (isComplete()) {
            return ImmutableSet.copyOf(rows);
        } else if (size == 0) {
            return ImmutableSet.of();
        } else {
            return this.rows.stream().filter(r -> this.isRowComplete(r)).collect(ImmutableSet.toImmutableSet());
        }
    }

    public ImmutableSet<C> getIncompleteColumns() {
        if (isComplete()) {
            return ImmutableSet.of();
        } else if (size == 0) {
            return ImmutableSet.copyOf(columns);
        } else {
            return this.columns.stream().filter(c -> !this.isColumnComplete(c)).collect(ImmutableSet.toImmutableSet());
        }
    }

    public Iterable<R> iterateUncheckedRows(C column) {
        return new Iterable<R>() {
            @Override
            public Iterator<R> iterator() {
                Iterator<R> rowIter = rows.iterator();

                return new Iterator<R>() {
                    R next = null;

                    @Override
                    public boolean hasNext() {
                        if (next == null) {
                            init();
                        }
                        return next != null;
                    }

                    @Override
                    public R next() {
                        if (next == null) {
                            init();
                        }
                        R result = next;
                        next = null;
                        return result;
                    }

                    private void init() {
                        while (rowIter.hasNext()) {
                            R candidate = rowIter.next();

                            if (!isChecked(candidate, column)) {
                                next = candidate;
                                break;
                            }
                        }
                    }
                };
            }
        };
    }

    @Override
    public String toString() {
        return toTableString("x", "");
    }

    public String toTableString(String checkedIndicator, String uncheckedIndicator) {
        StringBuilder result = new StringBuilder();

        int rowHeaderWidth = rows.stream().map((r) -> r.toString().length()).max(Comparator.naturalOrder()).get();

        result.append(padEnd("", rowHeaderWidth, ' '));
        result.append("|");

        int[] columnWidth = new int[columns.size()];

        int i = 0;
        for (C column : columns) {
            String columnLabel = column.toString();

            if (columnLabel.length() > 40) {
                columnLabel = columnLabel.substring(0, 40);
            }

            columnWidth[i] = columnLabel.length();
            i++;
            result.append(" ").append(columnLabel).append(" |");
        }

        result.append("\n");

        for (R row : rows) {

            result.append(padEnd(row.toString(), rowHeaderWidth, ' '));
            result.append("|");

            i = 0;
            for (C column : columns) {

                String v = isChecked(row, column) ? checkedIndicator : uncheckedIndicator;

                result.append(" ").append(padEnd(v, columnWidth[i], ' ')).append(" |");
                i++;
            }
            result.append("\n");

        }

        return result.toString();
    }

    static String padEnd(String string, int width, char paddingChar) {
        if (string.length() > width) {
            return string;
        }

        StringBuilder result = new StringBuilder(string);

        while (result.length() < width) {
            result.append(paddingChar);
        }

        return result.toString();
    }

    private CheckTable(Set<R> rows, Set<C> columns) {
        this.rows = rows;
        this.columns = columns;
        this.size = rows.size() * columns.size();
    }

    public static <R, C> CheckTable<R, C> create(Set<R> rows, Set<C> columns) {
        return new CheckTable<>(rows, columns);
    }
}
