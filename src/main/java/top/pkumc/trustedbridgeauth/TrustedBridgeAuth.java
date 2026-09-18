package top.pkumc.trustedbridgeauth;

import com.google.inject.Inject;
import com.velocitypowered.api.event.*;
import com.velocitypowered.api.event.connection.*;
import com.velocitypowered.api.event.player.*;
import com.velocitypowered.api.event.proxy.*;
import com.velocitypowered.api.network.*;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.*;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.util.GameProfile;

import net.kyori.adventure.text.Component;

import org.slf4j.Logger;

import java.io.*;
import java.nio.file.Path;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Client-bound, single-use transfers between two independently authenticated networks. */
public final class TrustedBridgeAuth {
    private final Logger logger;
    private final BridgeConfig config;
    private final LoginTicketExchange exchange;
    private final SecureRandom random = new SecureRandom();
    private final TicketStore tickets = new TicketStore(4096);
    private final ConcurrentMap<InboundConnection, HandoffProtocol.Decoded> approved =
            new ConcurrentHashMap<>();
    private final ConcurrentMap<UUID, String> arrivals = new ConcurrentHashMap<>();
    private final Set<UUID> departing = ConcurrentHashMap.newKeySet();
    private final Semaphore loginSlots = new Semaphore(64);
    private final AtomicLong rejected = new AtomicLong();
    private final ThreadPoolExecutor workers =
            new ThreadPoolExecutor(
                    4,
                    16,
                    30,
                    TimeUnit.SECONDS,
                    new SynchronousQueue<>(),
                    daemonThreads("bridge-worker"),
                    new ThreadPoolExecutor.AbortPolicy());
    private final ScheduledExecutorService timer =
            Executors.newSingleThreadScheduledExecutor(daemonThreads("bridge-timer"));
    private volatile BridgeLink link;
    private volatile boolean ready;

    @Inject
    public TrustedBridgeAuth(Logger logger, @DataDirectory Path directory) throws Exception {
        this.logger = logger;
        config = BridgeConfig.load(directory);
        exchange = new LoginTicketExchange();
    }

    @Subscribe
    public void initialize(ProxyInitializeEvent event) {
        try {
            link = new BridgeLink(config, this::receiveFrame, logger);
            link.start();
            ready = true;
            timer.scheduleAtFixedRate(this::cleanup, 5, 5, TimeUnit.SECONDS);
            logger.info(
                    "TrustedBridgeAuth ready: {} <-> {}; mutual TLS link; identity mode {}",
                    config.network(),
                    config.peer(),
                    config.identityMode());
        } catch (IOException | GeneralSecurityException e) {
            if (link != null) link.close();
            logger.error("Bridge unavailable; cross-network transfers disabled", e);
        }
    }

    @Subscribe
    public void shutdown(ProxyShutdownEvent event) {
        ready = false;
        if (link != null) link.close();
        workers.shutdownNow();
        timer.shutdownNow();
    }

    @Subscribe(order = PostOrder.LAST)
    public EventTask onServerPreConnect(ServerPreConnectEvent event) {
        RegisteredServer target = event.getResult().getServer().orElse(null);
        if (target == null || !target.getServerInfo().getName().equals(config.peer())) return null;
        // The peer entry selects a client transfer instead of a backend connection.
        event.setResult(ServerPreConnectEvent.ServerResult.denied());
        Player player = event.getPlayer();
        if (!ready
                || link == null
                || !link.connected()
                || player.getProtocolVersion().lessThan(ProtocolVersion.MINECRAFT_1_20_5)) {
            player.sendMessage(Component.text("跨服暂不可用，需要 Minecraft 1.20.5 或更高版本。"));
            return null;
        }
        if (!departing.add(player.getUniqueId())) return null;
        CompletableFuture<Void> done = new CompletableFuture<>();
        try {
            workers.execute(
                    () -> {
                        try {
                            byte[] ticket = new byte[HandoffProtocol.TICKET_LENGTH];
                            random.nextBytes(ticket);
                            long now = System.currentTimeMillis();
                            GameProfile profile = player.getGameProfile();
                            HandoffProtocol.Frame frame =
                                    HandoffProtocol.encode(
                                            profile,
                                            config.network(),
                                            config.peer(),
                                            now,
                                            now + config.ttlMillis(),
                                            HandoffProtocol.ticketHash(ticket),
                                            config.secret());
                            link.send(frame);
                            if (!player.isActive()
                                    || System.currentTimeMillis() >= now + config.ttlMillis())
                                throw new IOException("Player disconnected or handoff expired");
                            exchange.storeAndTransfer(
                                            player,
                                            ticket,
                                            config.transferHost(),
                                            config.transferPort())
                                    .get(config.timeoutMillis(), TimeUnit.MILLISECONDS);
                            logger.info(
                                    "Transfer requested: {} -> {} id={}",
                                    profile.getName(),
                                    config.peer(),
                                    HexFormat.of()
                                            .formatHex(HandoffProtocol.ticketHash(ticket))
                                            .substring(0, 12));
                        } catch (Exception e) {
                            player.sendMessage(Component.text("跨服验证失败，请稍后重试。"));
                            logger.warn(
                                    "Transfer to {} failed for {}: {}",
                                    config.peer(),
                                    player.getUsername(),
                                    e.toString());
                        } finally {
                            departing.remove(player.getUniqueId());
                            done.complete(null);
                        }
                    });
        } catch (RejectedExecutionException e) {
            departing.remove(player.getUniqueId());
            player.sendMessage(Component.text("跨服繁忙，请稍后重试。"));
            done.complete(null);
        }
        return EventTask.resumeWhenComplete(done);
    }

    @Subscribe(order = PostOrder.LAST)
    public EventTask onPreLogin(PreLoginEvent event) {
        if (event.getConnection().getHandshakeIntent() != HandshakeIntent.TRANSFER) return null;
        if (!event.getResult().isAllowed()) return null;
        event.setResult(
                PreLoginEvent.PreLoginComponentResult.denied(
                        Component.text("切服凭据无效或已过期，请从原服务器重新切服。")));
        if (!ready
                || event.getConnection()
                        .getProtocolVersion()
                        .lessThan(ProtocolVersion.MINECRAFT_1_20_5)
                || !loginSlots.tryAcquire()) return null;
        CompletableFuture<Void> done =
                exchange.request(event.getConnection(), config.timeoutMillis())
                        .handle(
                                (ticket, failure) -> {
                                    try {
                                        if (failure != null)
                                            throw new IOException(
                                                    "Client ticket exchange failed", failure);
                                        HandoffProtocol.Decoded handoff =
                                                tickets.consume(
                                                        ticket,
                                                        event.getUsername(),
                                                        System.currentTimeMillis());
                                        GameProfile profile = destinationProfile(handoff.profile());
                                        synchronized (approved) {
                                            if (approved.size() >= 4096)
                                                throw new IOException("Too many pending logins");
                                            approved.put(
                                                    event.getConnection(),
                                                    new HandoffProtocol.Decoded(
                                                            profile,
                                                            handoff.ticketHash(),
                                                            handoff.expiresAt()));
                                        }
                                        // The single-use ticket authenticates the source profile
                                        // independently of LoginStart UUID.
                                        event.setResult(
                                                PreLoginEvent.PreLoginComponentResult
                                                        .forceOfflineMode());
                                        logger.info(
                                                "Transfer verified: {} from {} id={}",
                                                profile.getName(),
                                                config.peer(),
                                                handoff.ticketHash().substring(0, 12));
                                    } catch (Exception e) {
                                        rejected.incrementAndGet();
                                        exchange.disconnect(
                                                event.getConnection(),
                                                "跨服身份验证失败，请从原服务器重新切服或联系管理员绑定账号。");
                                    } finally {
                                        loginSlots.release();
                                    }
                                    return null;
                                });
        return EventTask.resumeWhenComplete(done);
    }

    GameProfile destinationProfile(GameProfile source) throws IOException {
        UUID id =
                switch (config.identityMode()) {
                    case "source" -> source.getId();
                    case "mapped" -> config.identities().get(source.getId());
                    default -> null;
                };
        if (id == null) throw new IOException("No verified account mapping");
        return new GameProfile(id, source.getName(), source.getProperties());
    }

    @Subscribe(order = PostOrder.LAST)
    public EventTask onGameProfileRequest(GameProfileRequestEvent event) {
        if (event.getConnection().getHandshakeIntent() != HandshakeIntent.TRANSFER) return null;
        HandoffProtocol.Decoded handoff = approved.remove(event.getConnection());
        if (handoff == null || handoff.expiresAt() <= System.currentTimeMillis()) {
            return EventTask.resumeWhenComplete(exchange.reject(event.getConnection()));
        }
        event.setGameProfile(handoff.profile());
        arrivals.put(handoff.profile().getId(), handoff.ticketHash().substring(0, 12));
        return null;
    }

    @Subscribe
    public void onServerConnected(ServerConnectedEvent event) {
        String id = arrivals.remove(event.getPlayer().getUniqueId());
        if (id != null) {
            event.getPlayer().storeCookie(LoginTicketExchange.COOKIE, new byte[0]);
            logger.info(
                    "Transfer completed: {} -> {} UUID={} id={}",
                    event.getPlayer().getUsername(),
                    event.getServer().getServerInfo().getName(),
                    event.getPlayer().getUniqueId(),
                    id);
        }
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        String id = arrivals.remove(event.getPlayer().getUniqueId());
        if (id != null) logger.warn("Transfer ended before backend connection: id={}", id);
        departing.remove(event.getPlayer().getUniqueId());
    }

    private byte[] receiveFrame(HandoffProtocol.Frame frame) throws IOException {
        try {
            long now = System.currentTimeMillis();
            HandoffProtocol.Decoded handoff =
                    HandoffProtocol.verifyAndDecode(
                            frame.payload(),
                            frame.mac(),
                            config.secret(),
                            config.peer(),
                            config.network(),
                            now,
                            config.ttlMillis());
            // Identity policy validation precedes the acknowledgement and client transfer.
            destinationProfile(handoff.profile());
            tickets.register(handoff, frame.mac(), now);
            return HandoffProtocol.acknowledgement(frame, config.secret());
        } catch (IOException e) {
            rejected.incrementAndGet();
            throw e;
        }
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        tickets.cleanup(now);
        approved.forEach(
                (connection, handoff) -> {
                    if (handoff.expiresAt() <= now && approved.remove(connection, handoff))
                        exchange.disconnect(connection, "跨服凭据已过期，请重新切服。");
                });
        long count = rejected.getAndSet(0);
        if (count > 0)
            logger.warn(
                    "Rejected {} invalid/busy handoff or transfer attempts in the last 5 seconds",
                    count);
    }

    private static ThreadFactory daemonThreads(String prefix) {
        AtomicInteger seq = new AtomicInteger();
        return task -> {
            Thread thread = new Thread(task, prefix + "-" + seq.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
