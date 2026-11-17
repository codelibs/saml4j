/*
 * Copyright 2012-2026 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.saml4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

public class InMemoryReplayCacheTest {

    private static final class MutableClock extends Clock {

        private volatile Instant now;

        MutableClock(final Instant now) {
            this.now = now;
        }

        void advance(final Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static final Instant T0 = Instant.parse("2026-11-17T09:00:00Z");

    @Test
    public void testFirstRegistrationIsNewAndSecondIsKnown() {
        final MutableClock clock = new MutableClock(T0);
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, clock);
        assertFalse(cache.registerAndCheck("_id1", T0.plusSeconds(60)));
        assertTrue(cache.registerAndCheck("_id1", T0.plusSeconds(60)));
        assertTrue(cache.registerAndCheck("_id1", T0.plusSeconds(600)));
        assertEquals(1, cache.size());
    }

    @Test
    public void testDifferentIdsAreIndependent() {
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, new MutableClock(T0));
        assertFalse(cache.registerAndCheck("a", T0.plusSeconds(60)));
        assertFalse(cache.registerAndCheck("b", T0.plusSeconds(60)));
        assertFalse(cache.registerAndCheck("", T0.plusSeconds(60)));
        assertTrue(cache.registerAndCheck("a", T0.plusSeconds(60)));
        assertTrue(cache.registerAndCheck("b", T0.plusSeconds(60)));
        assertTrue(cache.registerAndCheck("", T0.plusSeconds(60)));
        assertEquals(3, cache.size());
    }

    @Test
    public void testIdsDifferingOnlyInCaseOrWhitespaceAreDifferent() {
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, new MutableClock(T0));
        assertFalse(cache.registerAndCheck("abc", T0.plusSeconds(60)));
        assertFalse(cache.registerAndCheck("ABC", T0.plusSeconds(60)));
        assertFalse(cache.registerAndCheck("abc ", T0.plusSeconds(60)));
        assertFalse(cache.registerAndCheck("é", T0.plusSeconds(60)));
        assertFalse(cache.registerAndCheck("é", T0.plusSeconds(60)));
        assertEquals(5, cache.size());
    }

    @Test
    public void testExpiredIdIsNewAgain() {
        final MutableClock clock = new MutableClock(T0);
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, clock);
        assertFalse(cache.registerAndCheck("_id1", T0.plusSeconds(60)));
        clock.advance(Duration.ofSeconds(59));
        assertTrue(cache.registerAndCheck("_id1", T0.plusSeconds(60)));
        clock.advance(Duration.ofSeconds(1));
        assertFalse(cache.registerAndCheck("_id1", T0.plusSeconds(120)));
        assertTrue(cache.registerAndCheck("_id1", T0.plusSeconds(120)));
        clock.advance(Duration.ofSeconds(59));
        assertTrue(cache.registerAndCheck("_id1", T0.plusSeconds(120)));
        clock.advance(Duration.ofSeconds(1));
        assertFalse(cache.registerAndCheck("_id1", T0.plusSeconds(180)));
    }

    @Test
    public void testSizeNeverExceedsTheMaximum() {
        final MutableClock clock = new MutableClock(T0);
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, clock);
        int largest = 0;
        for (int i = 0; i < 100_000; i++) {
            assertFalse(cache.registerAndCheck("id-" + i, T0.plusSeconds(3600 + i % 977)));
            largest = Math.max(largest, cache.size());
            assertTrue(cache.size() <= 100, "size " + cache.size() + " after " + i);
        }
        assertTrue(largest >= 90, "the cache should actually be used: " + largest);
    }

    @Test
    public void testSizeNeverExceedsTheMaximumWithMovingClock() {
        final MutableClock clock = new MutableClock(T0);
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, clock);
        for (int i = 0; i < 100_000; i++) {
            cache.registerAndCheck("id-" + i, clock.instant().plusSeconds(30));
            clock.advance(Duration.ofMillis(100));
            assertTrue(cache.size() <= 100);
        }
    }

    @Test
    public void testFullCacheDropsTheEntryThatExpiresFirst() {
        final InMemoryReplayCache cache = new InMemoryReplayCache(10, new MutableClock(T0));
        // registered in decreasing order of expiry: "id9" expires first although it is the newest
        for (int i = 0; i < 10; i++) {
            assertFalse(cache.registerAndCheck("id" + i, T0.plusSeconds(1000 - i)));
        }
        assertEquals(10, cache.size());
        assertFalse(cache.registerAndCheck("fresh", T0.plusSeconds(2000)));
        assertEquals(10, cache.size());
        assertTrue(cache.registerAndCheck("fresh", T0.plusSeconds(2000)));
        for (int i = 0; i < 9; i++) {
            assertTrue(cache.registerAndCheck("id" + i, T0.plusSeconds(1000 - i)), "id" + i + " must still be known");
        }
        assertFalse(cache.registerAndCheck("id9", T0.plusSeconds(991)), "id9 expired first and must have been dropped");
    }

    @Test
    public void testFullCacheDropsOnlyTheEarliestExpiringEntries() {
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, new MutableClock(T0));
        for (int i = 0; i < 100; i++) {
            assertFalse(cache.registerAndCheck("id" + (99 - i), T0.plusSeconds(1000 + 99 - i)));
        }
        assertFalse(cache.registerAndCheck("fresh", T0.plusSeconds(5000)));
        assertTrue(cache.size() <= 100);
        // whatever was dropped expires no later than anything that was kept
        boolean keptSeen = false;
        for (int i = 0; i < 100; i++) {
            final boolean known = cache.registerAndCheck("id" + i, T0.plusSeconds(1000 + i));
            if (known) {
                keptSeen = true;
            } else {
                assertFalse(keptSeen, "id" + i + " was dropped while an entry expiring earlier was kept");
            }
        }
        assertTrue(keptSeen);
    }

    @Test
    public void testExpiredEntriesAreDroppedBeforeLiveOnes() {
        final MutableClock clock = new MutableClock(T0);
        final InMemoryReplayCache cache = new InMemoryReplayCache(10, clock);
        for (int i = 0; i < 5; i++) {
            cache.registerAndCheck("old" + i, T0.plusSeconds(10));
        }
        for (int i = 0; i < 5; i++) {
            cache.registerAndCheck("live" + i, T0.plusSeconds(1000 + i));
        }
        clock.advance(Duration.ofSeconds(20));
        assertFalse(cache.registerAndCheck("fresh", T0.plusSeconds(2000)));
        for (int i = 0; i < 5; i++) {
            assertTrue(cache.registerAndCheck("live" + i, T0.plusSeconds(1000 + i)), "live" + i);
        }
        assertTrue(cache.registerAndCheck("fresh", T0.plusSeconds(2000)));
        assertEquals(6, cache.size());
    }

    @Test
    public void testNewEntryIsKeptWhenItExpiresBeforeEveryOtherEntry() {
        final InMemoryReplayCache cache = new InMemoryReplayCache(3, new MutableClock(T0));
        cache.registerAndCheck("a", T0.plusSeconds(500));
        cache.registerAndCheck("b", T0.plusSeconds(600));
        cache.registerAndCheck("c", T0.plusSeconds(700));
        assertFalse(cache.registerAndCheck("early", T0.plusSeconds(100)));
        assertTrue(cache.registerAndCheck("early", T0.plusSeconds(100)));
        assertEquals(3, cache.size());
    }

    @Test
    public void testSingleEntryCache() {
        final InMemoryReplayCache cache = new InMemoryReplayCache(1, new MutableClock(T0));
        assertFalse(cache.registerAndCheck("a", T0.plusSeconds(60)));
        assertTrue(cache.registerAndCheck("a", T0.plusSeconds(60)));
        assertFalse(cache.registerAndCheck("b", T0.plusSeconds(60)));
        assertEquals(1, cache.size());
        assertTrue(cache.registerAndCheck("b", T0.plusSeconds(60)));
    }

    @Test
    public void testLongIdCostsTheSameAsShortId() {
        final String big = "x".repeat(1024 * 1024);
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, new MutableClock(T0));
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            assertFalse(cache.registerAndCheck(big, T0.plusSeconds(60)));
            assertTrue(cache.registerAndCheck(big, T0.plusSeconds(60)));
            assertFalse(cache.registerAndCheck("short", T0.plusSeconds(60)));
            assertEquals(2, cache.size());
            // ids that differ only in the last character are different ids
            assertFalse(cache.registerAndCheck(big.substring(0, big.length() - 1) + "y", T0.plusSeconds(60)));
            assertEquals(3, cache.size());
            // many large ids: the cache keeps a bounded number of small entries
            for (int i = 0; i < 200; i++) {
                cache.registerAndCheck(big + i, T0.plusSeconds(60 + i));
                assertTrue(cache.size() <= 100);
            }
        });
    }

    @Test
    public void testConcurrentRegistrationOfOneIdIsNewExactlyOnce() throws Exception {
        final InMemoryReplayCache cache = new InMemoryReplayCache(1000, new MutableClock(T0));
        final int threads = 16;
        final ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int round = 0; round < 200; round++) {
                final String id = "_concurrent" + round;
                final CountDownLatch ready = new CountDownLatch(threads);
                final CountDownLatch go = new CountDownLatch(1);
                final AtomicInteger fresh = new AtomicInteger();
                final List<Future<?>> futures = new ArrayList<>();
                for (int t = 0; t < threads; t++) {
                    futures.add(pool.submit(() -> {
                        ready.countDown();
                        go.await();
                        if (!cache.registerAndCheck(id, T0.plusSeconds(60))) {
                            fresh.incrementAndGet();
                        }
                        return null;
                    }));
                }
                assertTrue(ready.await(10, TimeUnit.SECONDS));
                go.countDown();
                for (final Future<?> f : futures) {
                    f.get(10, TimeUnit.SECONDS);
                }
                assertEquals(1, fresh.get(), id);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void testConcurrentRegistrationOfManyIdsStaysBounded() throws Exception {
        final InMemoryReplayCache cache = new InMemoryReplayCache(100, new MutableClock(T0));
        final int threads = 16;
        final ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            final List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                final int n = t;
                futures.add(pool.submit(() -> {
                    for (int i = 0; i < 5000; i++) {
                        cache.registerAndCheck("t" + n + "-" + i, T0.plusSeconds(60 + i));
                    }
                    return null;
                }));
            }
            for (final Future<?> f : futures) {
                f.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertTrue(cache.size() <= 100, "size " + cache.size());
    }

    @Test
    public void testMaximumBelowOneIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayCache(0, Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayCache(-1, Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayCache(Integer.MIN_VALUE, Clock.systemUTC()));
    }

    @Test
    public void testDefaultConstructorWorks() {
        final InMemoryReplayCache cache = new InMemoryReplayCache();
        final Instant later = Instant.now().plusSeconds(60);
        assertFalse(cache.registerAndCheck("_id", later));
        assertTrue(cache.registerAndCheck("_id", later));
        assertEquals(10_000, InMemoryReplayCache.DEFAULT_MAX_ENTRIES);
    }
}
