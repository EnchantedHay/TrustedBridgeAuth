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
    private final PremiumIdentityClient identities;
    private final ConcurrentMap<Object, SessionIdentity> sessions = new ConcurrentHashMap<>();
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
        identities = config.identityMode().equals("local")
                ? new PremiumIdentityClient(directory, config.timeoutMillis()) : null;
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
        if (identities != null) identities.close();
    }

    @Subscribe(order = PostOrder.LAST)
    public EventTask onServerPreConnect(ServerPreConnectEvent event) {
        RegisteredServer target = event.getResult().getServer().orElse(null);
        if (target == null || !target.getServerInfo().getName().equals(config.peer())) return null;
        // The peer entry selects a client transfer instead of a backend connection.
        event.setResult(ServerPreConnectEvent.ServerResult.denied());
        Player player = event.getPlayer();
        if (player.getProtocolVersion().lessThan(ProtocolVersion.MINECRAFT_1_20_5)) {
            player.sendMessage(Component.text("跨服需要 Minecraft 1.20.5 或更高版本，请升级客户端。"));
            return null;
        }
        if (!ready || link == null || !link.connected()) {
            player.sendMessage(Component.text("跨服连接暂不可用，请稍后重试；持续失败请联系管理员。"));
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
                            SessionIdentity session = sessions.get(exchange.connectionKey(player));
                            if (session == null) throw new TransferFailure(TransferFailure.Reason.RELOGIN_REQUIRED);
                            GameProfile premium = null;
                            UUID localUuid = null;
                            String assurance = "none";
                            if (identities != null) {
                                PremiumIdentityClient.Identity identity = identities.resolve(profile.getId(), true, null);
                                premium = identity.premium();
                                localUuid = identity.local().getId();
                                assurance = identity.assurance();
                            } else if (config.identityMode().equals("premium")) {
                                if (!player.isOnlineMode() && !session.premium())
                                    throw new TransferFailure(TransferFailure.Reason.PREMIUM_REQUIRED);
                                premium = profile;
                                localUuid = session.localUuid();
                                assurance = session.premium() ? session.assurance() : "session";
                            }
                            now = System.currentTimeMillis();
                            HandoffProtocol.Frame frame =
                                    HandoffProtocol.encode(
                                            profile,
                                            session.loginName(), premium, localUuid, assurance,
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
                            player.sendMessage(Component.text(TransferFailure.message(e,
                                    "跨服连接中断或超时，请稍后重试；持续失败请联系管理员。")));
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
        if (!event.getResult().isAllowed()) return null;
        if (sessions.size() >= 4096) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("登录繁忙，请稍后重试。")));
            return null;
        }
        sessions.put(exchange.connectionKey(event.getConnection()),
                new SessionIdentity(event.getConnection(), event.getUsername(), null, false, "none"));
        if (event.getConnection().getHandshakeIntent() != HandshakeIntent.TRANSFER)
            return checkBindingLogin(event);
        event.setResult(
                PreLoginEvent.PreLoginComponentResult.denied(
                        Component.text("切服凭据无效或已过期，请从原服务器重新切服。")));
        if (!ready) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("跨服服务暂不可用，请返回原服务器稍后重试。")));
            return null;
        }
        if (event.getConnection().getProtocolVersion().lessThan(ProtocolVersion.MINECRAFT_1_20_5)) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("跨服需要 Minecraft 1.20.5 或更高版本，请升级客户端。")));
            return null;
        }
        if (!loginSlots.tryAcquire()) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("跨服繁忙，请返回原服务器稍后重试。")));
            return null;
        }
        CompletableFuture<Void> done =
                exchange.request(event.getConnection(), config.timeoutMillis())
                        .handleAsync(
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
                                        GameProfile profile = destinationProfile(handoff);
                                        synchronized (approved) {
                                            if (approved.size() >= 4096)
                                                throw new TransferFailure(TransferFailure.Reason.BUSY);
                                            approved.put(
                                                    event.getConnection(),
                                                    handoff.withProfile(profile));
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
                                                TransferFailure.message(e, "跳转凭据无效、已过期或连接中断，请返回原服务器重新跳转。"));
                                    }
                                    return null;
                                }, workers);
        done.whenComplete((value, failure) -> loginSlots.release());
        return EventTask.resumeWhenComplete(done);
    }

    private EventTask checkBindingLogin(PreLoginEvent event) {
        if (identities == null || event.getUniqueId() == null
                || event.getConnection().getProtocolVersion().lessThan(ProtocolVersion.MINECRAFT_1_20_5)) return null;
        CompletableFuture<Void> done = new CompletableFuture<>();
        try {
            workers.execute(() -> {
                try {
                    if (!identities.bindingCandidate(event.getUniqueId(), event.getUsername())) return;
                    event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("正版绑定验证结束，请回皮肤站确认。")));
                    String hash = exchange.premiumSession(event.getConnection(), config.timeoutMillis())
                            .get(config.timeoutMillis() + 1000L, TimeUnit.MILLISECONDS);
                    String code = identities.verifyLogin(event.getUsername(), hash);
                    exchange.disconnect(event.getConnection(), "正版登录验证成功。请勿转发验证码！\n"
                            + code + "\n请在 10 分钟内回皮肤站的正版绑定页面输入验证码。确认后重新加入。");
                } catch (Exception e) {
                    event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("正版绑定验证暂不可用，请稍后重试。")));
                    exchange.disconnect(event.getConnection(), "正版绑定验证暂不可用，请稍后重试。");
                    logger.warn("Premium binding login failed: {}", e.getClass().getSimpleName());
                } finally {
                    done.complete(null);
                }
            });
        } catch (RejectedExecutionException e) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text("登录繁忙，请稍后重试。")));
            done.complete(null);
        }
        return EventTask.resumeWhenComplete(done);
    }

    GameProfile destinationProfile(HandoffProtocol.Decoded handoff) throws IOException {
        if (Set.of("local", "premium").contains(config.identityMode())) {
            if (handoff.premium() == null) throw new IOException("Premium identity proof required");
            if (config.identityMode().equals("premium")) {
                if (handoff.localUuid() == null || !handoff.localUuid().equals(handoff.profile().getId()))
                    throw new IOException("Premium assertion must identify its local source");
                return handoff.premium();
            }
            if (!handoff.profile().getId().equals(handoff.premium().getId()))
                throw new IOException("Return source is not the verified premium identity");
            return identities.resolve(handoff.premium().getId(), false, handoff.localUuid()).local();
        }
        return destinationProfile(handoff.profile());
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
        sessions.put(exchange.connectionKey(event.getConnection()),
                new SessionIdentity(event.getConnection(), handoff.loginName(), handoff.localUuid(),
                        handoff.premium() != null, handoff.assurance()));
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
        sessions.remove(exchange.connectionKey(event.getPlayer()));
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
            destinationProfile(handoff);
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
        sessions.entrySet().removeIf(entry -> !entry.getValue().connection().isActive());
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

    private record SessionIdentity(InboundConnection connection, String loginName, UUID localUuid,
            boolean premium, String assurance) {}
}
