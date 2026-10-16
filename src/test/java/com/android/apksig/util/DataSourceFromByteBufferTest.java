/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.util;

import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for the {@link DataSource} returned by {@link DataSources#asDataSource(ByteBuffer)}.
 */
@RunWith(JUnit4.class)
public class DataSourceFromByteBufferTest extends DataSourceTestBase {

    @Test
    public void testChangesToBufferPosAndLimitNotVisible() throws Exception {
        ByteBuffer buf = ByteBuffer.wrap("abcdefgh".getBytes(StandardCharsets.UTF_8));
        buf.position(1);
        buf.limit(4);
        DataSource ds = DataSources.asDataSource(buf);
        buf.position(2);
        buf.limit(buf.capacity());
        assertGetByteBufferEquals("bcd", ds, 0, (int) ds.size());
        assertFeedEquals("bcd", ds, 0, (int) ds.size());
        assertSliceEquals("bcd", ds, 0, (int) ds.size());
        assertCopyToEquals("bcd", ds, 0, (int) ds.size());
    }

    @Test
    public void testGetByteBufferFromMultipleThreads() throws Exception {
        byte[] contents = new byte[256 * 1024];
        new Random(1).nextBytes(contents);
        DataSource ds = DataSources.asDataSource(ByteBuffer.wrap(contents));
        int chunkSize = 1024;
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < contents.length; i += chunkSize) {
                int offset = i;
                futures.add(
                        executor.submit(
                                () -> {
                                    byte[] chunk = new byte[chunkSize];
                                    ds.getByteBuffer(offset, chunkSize).get(chunk);
                                    assertArrayEquals(
                                            Arrays.copyOfRange(
                                                    contents, offset, offset + chunkSize),
                                            chunk);
                                    return null;
                                }));
            }
            for (Future<?> future : futures) {
                future.get();
            }
        } finally {
            executor.shutdown();
        }
    }

    @Override
    protected CloseableWithDataSource createDataSource(byte[] contents) throws IOException {
        return CloseableWithDataSource.of(DataSources.asDataSource(ByteBuffer.wrap(contents)));
    }
}
