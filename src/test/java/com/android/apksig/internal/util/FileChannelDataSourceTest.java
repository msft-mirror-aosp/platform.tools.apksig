/*
 * Copyright (C) 2019 The Android Open Source Project
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

package com.android.apksig.internal.util;

import static org.junit.Assert.assertArrayEquals;

import com.android.apksig.util.DataSource;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class FileChannelDataSourceTest {
    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void testFeedsCorrectData_whenFilePartiallyReadFromBeginning() throws Exception {
        byte[] fullFileContent = createFileContent(1024 * 1024 + 987654);
        RandomAccessFile raf = createRaf(fullFileContent);
        DataSource rafDataSource = new FileChannelDataSource(raf.getChannel());

        ByteArrayDataSink dataSink = new ByteArrayDataSink();

        int bytesToFeed = 1024 * 1024 + 12345;
        rafDataSource.feed(0, bytesToFeed, dataSink);

        byte[] expectedBytes = Arrays.copyOf(fullFileContent, bytesToFeed);

        byte[] resultBytes = getDataSinkBytes(dataSink);

        assertArrayEquals(expectedBytes, resultBytes);
    }

    @Test
    public void testFeedsCorrectData_whenFilePartiallyReadWithOffset() throws Exception {
        byte[] fullFileContent = createFileContent(1024 * 1024 + 987654);
        RandomAccessFile raf = createRaf(fullFileContent);
        DataSource rafDataSource = new FileChannelDataSource(raf.getChannel());

        ByteArrayDataSink dataSink = new ByteArrayDataSink();

        int offset = 23456;
        int bytesToFeed = 1024 * 1024 + 12345;
        rafDataSource.feed(offset, bytesToFeed, dataSink);

        byte[] expectedBytes = Arrays.copyOfRange(fullFileContent, offset, offset + bytesToFeed);

        byte[] resultBytes = getDataSinkBytes(dataSink);

        assertArrayEquals(expectedBytes, resultBytes);
    }

    @Test
    public void testFeedsCorrectData_whenSeveralMbRead() throws Exception {
        byte[] fullFileContent = createFileContent(3 * 1024 * 1024 + 987654);
        RandomAccessFile raf = createRaf(fullFileContent);
        DataSource rafDataSource = new FileChannelDataSource(raf.getChannel());

        ByteArrayDataSink dataSink = new ByteArrayDataSink();

        int offset = 23456;
        int bytesToFeed = 2 * 1024 * 1024 + 12345;
        rafDataSource.feed(offset, bytesToFeed, dataSink);

        byte[] expectedBytes = Arrays.copyOfRange(fullFileContent, offset, offset + bytesToFeed);

        byte[] resultBytes = getDataSinkBytes(dataSink);

        assertArrayEquals(expectedBytes, resultBytes);
    }

    @Test
    public void testCopyToCorrectData_whenReadConcurrently() throws Exception {
        byte[] fullFileContent = createFileContent(1024 * 1024);
        RandomAccessFile raf = createRaf(fullFileContent);
        DataSource rafDataSource = new FileChannelDataSource(raf.getChannel());

        int chunkSize = 4096;
        int chunkCount = fullFileContent.length / chunkSize;
        ByteBuffer result = ByteBuffer.allocate(fullFileContent.length);
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < chunkCount; i++) {
                int offset = i * chunkSize;
                futures.add(
                        executor.submit(
                                () -> {
                                    ByteBuffer chunk = result.duplicate();
                                    chunk.position(offset);
                                    rafDataSource.copyTo(offset, chunkSize, chunk);
                                    return null;
                                }));
            }
            for (Future<?> future : futures) {
                future.get();
            }
        } finally {
            executor.shutdown();
        }

        assertArrayEquals(fullFileContent, result.array());
    }

    @Test(expected = IOException.class)
    public void testCopyToThrows_whenFileShorterThanSource() throws Exception {
        byte[] fullFileContent = createFileContent(1000);
        RandomAccessFile raf = createRaf(fullFileContent);
        DataSource rafDataSource =
                new FileChannelDataSource(raf.getChannel(), 0, fullFileContent.length + 10);

        rafDataSource.copyTo(0, fullFileContent.length + 10, ByteBuffer.allocate(2000));
    }

    private static byte[] getDataSinkBytes(ByteArrayDataSink dataSink) {
        ByteBuffer result = dataSink.getByteBuffer(0, (int)dataSink.size());
        byte[] resultBytes = new byte[result.limit()];
        result.get(resultBytes);
        return resultBytes;
    }

    private static byte[] createFileContent(int fileSize) {
        byte[] fullFileContent = new byte[fileSize];
        for (int i = 0; i < fileSize; ++i) {
            fullFileContent[i] = (byte) (i % 255);
        }
        return fullFileContent;
    }

    private RandomAccessFile createRaf(byte[] content) throws Exception {
        File dataFile = temporaryFolder.newFile();

        try (FileOutputStream fos = new FileOutputStream(dataFile)) {
            fos.write(content);
        }
        return new RandomAccessFile(dataFile, "r");
    }
}
