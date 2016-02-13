/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.support;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import org.apache.lucene.util.BytesRef;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.geo.GeoPoint;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.Streamable;
import org.elasticsearch.common.text.Text;

public class DebugStreamOutput extends BytesStreamOutput {

    @Override
    public void writeBytes(final byte[] b) throws IOException {
        System.out.print(new String(b));
        super.writeBytes(b);
    }

    @Override
    public void writeBytes(final byte[] b, final int length) throws IOException {
        System.out.print(new String(b, 0, length));
        super.writeBytes(b, length);
    }

    @Override
    public void writeByteArray(final byte[] b) throws IOException {
        System.out.print(new String(b));
        super.writeByteArray(b);
    }

    @Override
    public void writeBytesReference(final BytesReference bytes) throws IOException {
        System.out.print(bytes.toUtf8());
        super.writeBytesReference(bytes);
    }

    @Override
    public void writeBytesRef(final BytesRef bytes) throws IOException {
        System.out.print(bytes.utf8ToString());
        super.writeBytesRef(bytes);
    }

    @Override
    public void writeInt(final int i) throws IOException {
        System.out.print(i);
        super.writeInt(i);
    }

    @Override
    public void writeVInt(final int i) throws IOException {
        System.out.print(i);
        super.writeVInt(i);
    }

    @Override
    public void writeLong(final long i) throws IOException {
        System.out.print(i);
        super.writeLong(i);
    }

    @Override
    public void writeVLong(final long i) throws IOException {
        System.out.print(i);
        super.writeVLong(i);
    }

    @Override
    public void writeOptionalString(final String str) throws IOException {
        System.out.print(str);
        super.writeOptionalString(str);
    }

    @Override
    public void writeOptionalVInt(final Integer integer) throws IOException {
        System.out.print(integer);
        super.writeOptionalVInt(integer);
    }

    @Override
    public void writeOptionalText(final Text text) throws IOException {
        System.out.print(text.string());
        super.writeOptionalText(text);
    }

    @Override
    public void writeText(final Text text) throws IOException {
        System.out.print(text.string());
        super.writeText(text);
    }

    @Override
    public void writeString(final String str) throws IOException {
        System.out.print(str);
        super.writeString(str);
    }

    @Override
    public void writeFloat(final float v) throws IOException {
        System.out.print(v);
        super.writeFloat(v);
    }

    @Override
    public void writeDouble(final double v) throws IOException {
        System.out.print(v);
        super.writeDouble(v);
    }

    @Override
    public void writeBoolean(final boolean b) throws IOException {
        System.out.print(b);
        super.writeBoolean(b);
    }

    @Override
    public void writeOptionalBoolean(final Boolean b) throws IOException {
        System.out.print(b);
        super.writeOptionalBoolean(b);
    }

    @Override
    public void write(final int b) throws IOException {
        System.out.print(b);
        super.write(b);
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException {
        System.out.print(new String(b, off, len));
        super.write(b, off, len);
    }

    @Override
    public void writeStringArray(final String[] array) throws IOException {
        System.out.print(Arrays.toString(array));
        super.writeStringArray(array);
    }

    @Override
    public void writeStringArrayNullable(final String[] array) throws IOException {
        System.out.print(Arrays.toString(array));
        super.writeStringArrayNullable(array);
    }

    @Override
    public void writeMap(final Map<String, Object> map) throws IOException {
        System.out.print(map);
        super.writeMap(map);
    }

    @Override
    public void writeGenericValue(final Object value) throws IOException {
        System.out.print(String.valueOf(value));
        super.writeGenericValue(value);
    }

    @Override
    public void writeIntArray(final int[] values) throws IOException {
        System.out.print(Arrays.toString(values));
        super.writeIntArray(values);
    }

    @Override
    public void writeLongArray(final long[] values) throws IOException {
        System.out.print(Arrays.toString(values));
        super.writeLongArray(values);
    }

    @Override
    public void writeFloatArray(final float[] values) throws IOException {
        System.out.print(Arrays.toString(values));
        super.writeFloatArray(values);
    }

    @Override
    public void writeDoubleArray(final double[] values) throws IOException {
        System.out.print(Arrays.toString(values));
        super.writeDoubleArray(values);
    }

    @Override
    public void writeOptionalStreamable(final Streamable streamable) throws IOException {
        System.out.println("(#streamable#)");
        super.writeOptionalStreamable(streamable);
    }

    @Override
    public void writeThrowable(final Throwable throwable) throws IOException {
        System.out.print(throwable);
        super.writeThrowable(throwable);
    }

    @Override
    public void writeGeoPoint(final GeoPoint geoPoint) throws IOException {
        System.out.print(geoPoint);
        super.writeGeoPoint(geoPoint);
    }

}
