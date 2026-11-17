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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * A {@link ReplayCache} held in the memory of one JVM. IDs are kept as SHA-256 digests, so an entry costs the same
 * whatever the length of the ID, and the number of entries is bounded: when the cache is full, expired entries are dropped, and if that does not
 * make room, the tenth of the entries that expire first.
 */
public class InMemoryReplayCache implements ReplayCache {

    /** The default number of entries. */
    public static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final int maxEntries;

    private final Clock clock;

    private final Map<String, Instant> entries = new HashMap<>();

    /**
     * Creates a cache with the default size.
     */
    public InMemoryReplayCache() {
        this(DEFAULT_MAX_ENTRIES, Clock.systemUTC());
    }

    /**
     * Creates a cache.
     *
     * @param maxEntries the largest number of entries kept, at least 1
     * @param clock the clock
     */
    public InMemoryReplayCache(final int maxEntries, final Clock clock) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock is required");
        }
        this.maxEntries = maxEntries;
        this.clock = clock;
    }

    @Override
    public synchronized boolean registerAndCheck(final String id, final Instant expiresAt) {
        if (id == null || expiresAt == null) {
            throw new IllegalArgumentException("id and expiresAt are required");
        }
        final Instant now = clock.instant();
        final String key = digest(id);
        final Instant known = entries.get(key);
        if (known != null && known.isAfter(now)) {
            return true;
        }
        if (entries.size() >= maxEntries) {
            evict(now);
        }
        entries.put(key, expiresAt);
        return false;
    }

    /**
     * Returns the number of entries held.
     *
     * @return the number of entries
     */
    public synchronized int size() {
        return entries.size();
    }

    private void evict(final Instant now) {
        for (final Iterator<Map.Entry<String, Instant>> it = entries.entrySet().iterator(); it.hasNext();) {
            if (!it.next().getValue().isAfter(now)) {
                it.remove();
            }
        }
        if (entries.size() < maxEntries) {
            return;
        }
        final PriorityQueue<Map.Entry<String, Instant>> queue = new PriorityQueue<>(Map.Entry.comparingByValue());
        queue.addAll(entries.entrySet());
        final int drop = Math.max(1, maxEntries / 10);
        for (int i = 0; i < drop && !queue.isEmpty(); i++) {
            entries.remove(queue.poll().getKey());
        }
    }

    private static String digest(final String id) {
        try {
            final byte[] d = MessageDigest.getInstance("SHA-256").digest(id.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(d);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
