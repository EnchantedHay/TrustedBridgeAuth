package top.pkumc.trustedbridgeauth;

import java.io.*;
import java.nio.file.*;
import java.util.*;

record BridgeConfig(
        String network,
        String peer,
        String peerHost,
        int bridgePort,
        String role,
        String transferHost,
        int transferPort,
        String listenAddress,
        int timeoutMillis,
        long ttlMillis,
        byte[] secret,
        String identityMode,
        Map<UUID, UUID> identities,
        Path tlsDirectory) {
    static BridgeConfig load(Path directory) throws IOException {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(directory.resolve("config.properties"))) {
            p.load(r);
        }
        String network = required(p, "network-id"), peer = required(p, "peer-id");
        if (!network.matches("[a-z0-9_-]{1,32}")
                || !peer.matches("[a-z0-9_-]{1,32}")
                || network.equals(peer)) throw new IOException("Invalid network identities");
        Path root = directory.toAbsolutePath().getParent().getParent();
        Path secretFile = root.resolve(required(p, "handoff-secret-file")).normalize();
        String raw = Files.readString(secretFile).trim();
        byte[] secret =
                raw.matches("[a-fA-F0-9]{64,}") && raw.length() % 2 == 0
                        ? HexFormat.of().parseHex(raw)
                        : raw.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (secret.length < 32) throw new IOException("Handoff key must have at least 32 bytes");
        int ttl = number(p, "handoff-ttl-seconds", 30, 10, 60);
        String mode = p.getProperty("identity-mode", "mapped").trim();
        if (!Set.of("mapped", "source", "local", "premium").contains(mode))
            throw new IOException("Invalid identity mode");
        Map<UUID, UUID> mappings = new HashMap<>();
        Path mappingFile = directory.resolve("identity-map.properties");
        if (mode.equals("mapped") && Files.exists(mappingFile)) {
            Properties entries = new Properties();
            try (Reader r = Files.newBufferedReader(mappingFile)) {
                entries.load(r);
            }
            for (String key : entries.stringPropertyNames())
                mappings.put(
                        UUID.fromString(key), UUID.fromString(entries.getProperty(key).trim()));
        }
        String role = required(p, "bridge-role");
        if (!Set.of("listen", "connect").contains(role))
            throw new IOException("Invalid bridge-role");
        String peerHost = role.equals("connect") ? required(p, "bridge-host") : "";
        String transferHost = required(p, "transfer-host");
        if (transferHost.toLowerCase(Locale.ROOT).endsWith(".invalid"))
            throw new IOException("Missing reachable transfer-host");
        return new BridgeConfig(
                network,
                peer,
                peerHost,
                number(p, "bridge-port", 27000, 1, 65535),
                role,
                transferHost,
                number(p, "transfer-port", 25565, 1, 65535),
                p.getProperty("bridge-listen-address", "0.0.0.0").trim(),
                number(p, "timeout-millis", 5000, 1000, 10000),
                ttl * 1000L,
                secret,
                mode,
                Map.copyOf(mappings),
                directory.resolve("tls"));
    }

    private static String required(Properties p, String key) throws IOException {
        String value = p.getProperty(key, "").trim();
        if (value.isEmpty()) throw new IOException("Missing " + key);
        return value;
    }

    private static int number(Properties p, String key, int fallback, int min, int max)
            throws IOException {
        int value;
        try {
            value = Integer.parseInt(p.getProperty(key, Integer.toString(fallback)).trim());
        } catch (NumberFormatException e) {
            throw new IOException("Invalid " + key, e);
        }
        if (value < min || value > max) throw new IOException("Invalid " + key);
        return value;
    }
}
