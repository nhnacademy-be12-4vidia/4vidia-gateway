package com.nhnacademy._vidiagateway.filter;

public class SnowflakeIdGenerator {
    private static final long EPOCH = 1609459200000L; // 2021-01-01
    private static long sequence = 0L;
    private static long lastTimestamp = -1L;

    public static synchronized long nextId() {
        long now = System.currentTimeMillis();

        if (now == lastTimestamp) {
            sequence = (sequence + 1) & 4095;  // 12비트 (0~4095)
            if (sequence == 0) {
                while ((now = System.currentTimeMillis()) <= lastTimestamp) {
                    // wait until next millisecond
                }
            }
        } else {
            sequence = 0L;
        }

        lastTimestamp = now;

        return ((now - EPOCH) << 22) | sequence;
    }
}
