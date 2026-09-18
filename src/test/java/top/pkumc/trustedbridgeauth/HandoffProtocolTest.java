package top.pkumc.trustedbridgeauth;

import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.network.*;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.util.GameProfile;

import org.slf4j.Logger;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dependency-free regressions; executed by build.sh and Gradle check. Synthetic identities only.
 */
public final class HandoffProtocolTest {
    static int assertions;
    static final long NOW = 1_800_000_000_000L;
    static final byte[] SECRET = new byte[32], TICKET = new byte[32];
    static final GameProfile PROFILE =
            new GameProfile(
                    UUID.fromString("00000000-0000-4000-8000-000000000001"),
                    "AuditUser",
                    List.of(new GameProfile.Property("textures", "value", "signature")));

    static HandoffProtocol.Frame frame(long issued, long expires) throws Exception {
        return HandoffProtocol.encode(
                PROFILE,
                "pkumc",
                "thunion",
                issued,
                expires,
                HandoffProtocol.ticketHash(TICKET),
                SECRET);
    }

    static HandoffProtocol.Decoded decode(HandoffProtocol.Frame f, long now) throws IOException {
        return HandoffProtocol.verifyAndDecode(
                f.payload(), f.mac(), SECRET, "pkumc", "thunion", now, 30000);
    }

    static void require(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }

    static void fails(Task task) throws Exception {
        assertions++;
        try {
            task.run();
        } catch (IOException expected) {
            return;
        }
        throw new AssertionError("Expected rejection");
    }

    interface Task {
        void run() throws Exception;
    }

    public static void main(String[] args) throws Exception {
        HandoffProtocol.Frame f = frame(NOW, NOW + 30000);
        HandoffProtocol.Decoded decoded = decode(f, NOW);
        require(
                decoded.profile().getId().equals(PROFILE.getId())
                        && decoded.profile().getName().equals(PROFILE.getName())
                        && decoded.profile()
                                .getProperties()
                                .getFirst()
                                .getSignature()
                                .equals("signature"),
                "profile round trip");
        require(decoded.expiresAt() == NOW + 30000, "signed deadline preserved");
        byte[] tampered = f.payload().clone();
        tampered[tampered.length - 1] ^= 1;
        fails(
                () ->
                        HandoffProtocol.verifyAndDecode(
                                tampered, f.mac(), SECRET, "pkumc", "thunion", NOW, 30000));
        byte[] wrongKey = SECRET.clone();
        wrongKey[0] = 1;
        fails(
                () ->
                        HandoffProtocol.verifyAndDecode(
                                f.payload(), f.mac(), wrongKey, "pkumc", "thunion", NOW, 30000));
        fails(
                () ->
                        HandoffProtocol.verifyAndDecode(
                                f.payload(), f.mac(), SECRET, "wrong", "thunion", NOW, 30000));
        fails(
                () ->
                        HandoffProtocol.verifyAndDecode(
                                f.payload(), f.mac(), SECRET, "pkumc", "wrong", NOW, 30000));
        fails(() -> decode(f, NOW + 30000));
        fails(() -> decode(frame(NOW + 5001, NOW + 30000), NOW));
        fails(() -> decode(frame(NOW, NOW + 30001), NOW));
        fails(() -> decode(frame(NOW, NOW), NOW));
        byte[] old = f.payload().clone();
        old[3] = 0x31;
        fails(
                () ->
                        HandoffProtocol.verifyAndDecode(
                                old,
                                HandoffProtocol.hmac(old, SECRET),
                                SECRET,
                                "pkumc",
                                "thunion",
                                NOW,
                                30000));
        byte[] trailing = Arrays.copyOf(f.payload(), f.payload().length + 1);
        fails(
                () ->
                        HandoffProtocol.verifyAndDecode(
                                trailing,
                                HandoffProtocol.hmac(trailing, SECRET),
                                SECRET,
                                "pkumc",
                                "thunion",
                                NOW,
                                30000));
        fails(
                () ->
                        HandoffProtocol.encode(
                                new GameProfile(
                                        PROFILE.getId(),
                                        PROFILE.getName(),
                                        List.of(
                                                new GameProfile.Property(
                                                        "textures", "x".repeat(17000), ""))),
                                "pkumc",
                                "thunion",
                                NOW,
                                NOW + 30000,
                                HandoffProtocol.ticketHash(TICKET),
                                SECRET));
        require(
                !Arrays.equals(f.mac(), HandoffProtocol.acknowledgement(f, SECRET)),
                "ACK domain separation");
        require(
                !Arrays.equals(
                        HandoffProtocol.acknowledgement(f, SECRET),
                        HandoffProtocol.acknowledgement(frame(NOW, NOW + 20000), SECRET)),
                "ACK frame binding");
        TicketStore store = new TicketStore(1);
        store.register(decoded, f.mac(), NOW);
        store.register(decoded, f.mac(), NOW + 1);
        byte[] other = new byte[32];
        other[0] = 1;
        fails(() -> store.consume(other, PROFILE.getName(), NOW));
        fails(() -> store.consume(TICKET, "OtherName", NOW));
        fails(() -> store.consume(null, PROFILE.getName(), NOW));
        fails(() -> store.consume(new byte[31], PROFILE.getName(), NOW));
        require(
                store.consume(TICKET, PROFILE.getName(), NOW)
                        .profile()
                        .getId()
                        .equals(PROFILE.getId()),
                "valid holder accepted");
        fails(() -> store.consume(TICKET, PROFILE.getName(), NOW));
        fails(() -> store.register(decoded, f.mac(), NOW));
        TicketStore expired = new TicketStore(1);
        expired.register(decoded, f.mac(), NOW);
        fails(() -> expired.consume(TICKET, PROFILE.getName(), NOW + 30000));
        fails(() -> expired.register(decoded, f.mac(), NOW + 30000));
        HandoffProtocol.Frame another =
                HandoffProtocol.encode(
                        PROFILE,
                        "pkumc",
                        "thunion",
                        NOW,
                        NOW + 30000,
                        HandoffProtocol.ticketHash(other),
                        SECRET);
        fails(() -> store.register(decode(another, NOW), another.mac(), NOW));
        TicketStore race = new TicketStore(16);
        race.register(decoded, f.mac(), NOW);
        AtomicInteger successes = new AtomicInteger();
        try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
            List<Future<?>> jobs = new ArrayList<>();
            for (int i = 0; i < 32; i++)
                jobs.add(
                        pool.submit(
                                () -> {
                                    try {
                                        race.consume(TICKET, PROFILE.getName(), NOW);
                                        successes.incrementAndGet();
                                    } catch (IOException expected) {
                                    }
                                }));
            for (Future<?> job : jobs) job.get();
        }
        require(successes.get() == 1, "exactly one concurrent consumer");
        testOrdinaryLogin();
        System.out.println(
                "PASS: "
                        + assertions
                        + " protocol, replay, expiry, resource-bound and ordinary-login checks");
    }

    static void testOrdinaryLogin() throws Exception {
        Path root = Files.createTempDirectory("bridge-regression-");
        try {
            Path data = root.resolve("plugins/trusted-bridge-auth");
            Files.createDirectories(data);
            Files.writeString(root.resolve("test.secret"), "0".repeat(64));
            Files.writeString(
                    data.resolve("config.properties"),
                    "network-id=thunion\n"
                        + "peer-id=pkumc\n"
                        + "bridge-role=connect\n"
                        + "bridge-host=127.0.0.1\n"
                        + "transfer-host=127.0.0.1\n"
                        + "handoff-secret-file=test.secret\n"
                        + "identity-mode=source\n");
            Logger log =
                    (Logger)
                            Proxy.newProxyInstance(
                                    Logger.class.getClassLoader(),
                                    new Class<?>[] {Logger.class},
                                    (p, m, a) -> m.getReturnType() == boolean.class ? false : null);
            TrustedBridgeAuth plugin = new TrustedBridgeAuth(log, data);
            InboundConnection conn =
                    (InboundConnection)
                            Proxy.newProxyInstance(
                                    InboundConnection.class.getClassLoader(),
                                    new Class<?>[] {InboundConnection.class},
                                    (p, m, a) ->
                                            switch (m.getName()) {
                                                case "getHandshakeIntent" -> HandshakeIntent.LOGIN;
                                                case "getProtocolVersion" ->
                                                        ProtocolVersion.MINECRAFT_1_20_5;
                                                default -> null;
                                            });
            PreLoginEvent event = new PreLoginEvent(conn, PROFILE.getName(), PROFILE.getId());
            require(plugin.onPreLogin(event) == null, "ordinary login cannot request handoff");
            require(!event.getResult().isForceOfflineMode(), "ordinary login keeps authentication");
            require(
                    plugin.destinationProfile(PROFILE).getId().equals(PROFILE.getId()),
                    "source identity policy");
            plugin.shutdown(null);
            String config = Files.readString(data.resolve("config.properties"));
            require(BridgeConfig.load(data).bridgePort() == 27000, "shared control port default");
            Files.writeString(
                    data.resolve("config.properties"),
                    config.replace("transfer-host=127.0.0.1", "transfer-host=entrypoint.invalid"));
            fails(() -> BridgeConfig.load(data));
            Files.writeString(data.resolve("config.properties"), config + "bridge-port=invalid\n");
            fails(() -> BridgeConfig.load(data));
            Files.writeString(
                    data.resolve("config.properties"),
                    config.replace("bridge-role=connect", "bridge-role=invalid"));
            fails(() -> BridgeConfig.load(data));
            Files.writeString(
                    data.resolve("config.properties"),
                    config.replace("identity-mode=source", "identity-mode=mapped"));
            TrustedBridgeAuth unmapped = new TrustedBridgeAuth(log, data);
            try {
                fails(() -> unmapped.destinationProfile(PROFILE));
            } finally {
                unmapped.shutdown(null);
            }
            UUID local = UUID.fromString("00000000-0000-4000-8000-000000000002");
            Files.writeString(
                    data.resolve("identity-map.properties"), PROFILE.getId() + "=" + local + "\n");
            TrustedBridgeAuth mapped = new TrustedBridgeAuth(log, data);
            try {
                require(
                        mapped.destinationProfile(PROFILE).getId().equals(local),
                        "verified mapping uses destination UUID");
                require(
                        mapped.destinationProfile(PROFILE).getName().equals(PROFILE.getName()),
                        "mapping preserves authenticated name");
            } finally {
                mapped.shutdown(null);
            }
            Files.writeString(
                    data.resolve("config.properties"),
                    config.replace("identity-mode=source", "identity-mode=offline"));
            fails(() -> BridgeConfig.load(data));
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(p);
            }
        }
    }
}
