package top.pkumc.trustedbridgeauth;

import org.slf4j.Logger;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** Serializes status logging and deduplicates errors until the next successful connection. */
final class BridgeStatus {
    private static final int MAX_ERRORS = 128;
    private final Logger logger;
    private final String peer;
    private final Set<String> errors = new HashSet<>();
    private long offlineSince;
    private boolean offline;
    private boolean connected;
    private boolean saturated;

    BridgeStatus(Logger logger, String peer) {
        this.logger = logger;
        this.peer = peer;
    }

    synchronized void failed(Throwable error) {
        String reason = reason(error);
        if (!offline && !connected) {
            offline = true;
            offlineSince = System.nanoTime();
            errors.add(reason);
            logger.warn("Bridge unavailable: {}; automatic reconnect enabled; cause={}", peer, reason);
        } else if (errors.contains(reason)) {
            return;
        } else if (errors.size() < MAX_ERRORS) {
            errors.add(reason);
            logger.warn("Bridge new error: {}; cause={}", peer, reason);
        } else if (!saturated) {
            saturated = true;
            logger.warn("Bridge error limit reached: {}; further errors suppressed until connection state changes", peer);
        }
    }

    synchronized void disconnected(Throwable error) {
        if (offline) {
            failed(error);
            return;
        }
        offline = true;
        connected = false;
        errors.clear();
        saturated = false;
        offlineSince = System.nanoTime();
        String reason = reason(error);
        errors.add(reason);
        logger.warn("Bridge disconnected: {}; automatic reconnect enabled; cause={}", peer, reason);
    }

    synchronized void connected(String network) {
        if (offline) {
            logger.info("Bridge restored: {} <-> {} via mutual TLS 1.3; offline={}s",
                    network, peer, TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - offlineSince));
        } else {
            logger.info("Bridge connected: {} <-> {} via mutual TLS 1.3", network, peer);
        }
        offline = false;
        connected = true;
        errors.clear();
        saturated = false;
    }

    private static String reason(Throwable error) {
        String message = error.getMessage();
        StringBuilder text = new StringBuilder(error.getClass().getSimpleName());
        if (message != null && !message.isBlank()) {
            text.append(": ");
            for (int i = 0; i < Math.min(message.length(), 256); i++) {
                char c = message.charAt(i);
                text.append(Character.isISOControl(c) || c == '\u2028' || c == '\u2029' ? ' ' : c);
            }
        }
        return text.toString();
    }
}
