package top.pkumc.trustedbridgeauth;

import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.connection.client.ConnectedPlayer;
import com.velocitypowered.proxy.connection.client.LoginInboundConnection;
import com.velocitypowered.proxy.crypto.EncryptionUtils;
import com.velocitypowered.proxy.protocol.packet.*;

import io.netty.channel.*;
import io.netty.util.ReferenceCountUtil;

import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;

import java.lang.reflect.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.concurrent.*;

/**
 * Velocity 4.2.1-b31 internal API adapter for encrypted login cookies and ordered transfers.
 * Adapter initialization requires compatible internals; cookie requests require encryption.
 */
final class LoginTicketExchange {
    static final Key COOKIE = Key.key("pkumc", "trusted_bridge_v2");
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Method connectionMethod;
    private final Field authenticateField;

    LoginTicketExchange() throws ReflectiveOperationException {
        connectionMethod = LoginInboundConnection.class.getDeclaredMethod("delegatedConnection");
        connectionMethod.setAccessible(true);
        authenticateField = EncryptionRequestPacket.class.getDeclaredField("shouldAuthenticate");
        authenticateField.setAccessible(true);
    }

    private MinecraftConnection connection(InboundConnection inbound)
            throws ReflectiveOperationException {
        if (inbound instanceof ConnectedPlayer player) return player.getConnection();
        return (MinecraftConnection) connectionMethod.invoke(inbound);
    }

    Object connectionKey(InboundConnection inbound) {
        try {
            return connection(inbound);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unsupported connection", e);
        }
    }

    void disconnect(InboundConnection inbound, String message) {
        if (inbound instanceof LoginInboundConnection login)
            login.disconnect(Component.text(message));
    }

    CompletableFuture<Void> reject(InboundConnection inbound) {
        CompletableFuture<Void> done = new CompletableFuture<>();
        try {
            MinecraftConnection mc = connection(inbound);
            mc.eventLoop()
                    .execute(
                            () ->
                                    mc.getChannel()
                                            .close()
                                            .addListener(closed -> done.complete(null)));
        } catch (Exception e) {
            done.completeExceptionally(e);
        }
        return done;
    }

    CompletableFuture<Void> storeAndTransfer(Player player, byte[] ticket, String host, int port) {
        CompletableFuture<Void> result = new CompletableFuture<>();
        MinecraftConnection mc = ((ConnectedPlayer) player).getConnection();
        mc.eventLoop()
                .execute(
                        () -> {
                            try {
                                // A completed cookie write precedes the public, cancellable
                                // transfer event.
                                mc.write(new ClientboundStoreCookiePacket(COOKIE, ticket))
                                        .addListener(
                                                write -> {
                                                    if (!write.isSuccess()) {
                                                        result.completeExceptionally(write.cause());
                                                        return;
                                                    }
                                                    try {
                                                        player.transferToHost(
                                                                InetSocketAddress.createUnresolved(
                                                                        host, port));
                                                        result.complete(null);
                                                    } catch (Exception e) {
                                                        result.completeExceptionally(e);
                                                    }
                                                });
                            } catch (Exception e) {
                                result.completeExceptionally(e);
                            }
                        });
        return result;
    }

    CompletableFuture<byte[]> request(InboundConnection inbound, int timeoutMillis) {
        return request(inbound, timeoutMillis, false);
    }

    CompletableFuture<String> premiumSession(InboundConnection inbound, int timeoutMillis) {
        return request(inbound, timeoutMillis, true).thenApply(
                bytes -> new String(bytes, java.nio.charset.StandardCharsets.US_ASCII));
    }

    private CompletableFuture<byte[]> request(InboundConnection inbound, int timeoutMillis, boolean authenticate) {
        CompletableFuture<byte[]> result = new CompletableFuture<>();
        try {
            MinecraftConnection mc = connection(inbound);
            mc.eventLoop()
                    .execute(
                            () -> {
                                try {
                                    if (mc.isClosed())
                                        throw new IllegalStateException("Connection closed");
                                    ChannelPipeline pipeline = mc.getChannel().pipeline();
                                    String name = "trusted-bridge-ticket";
                                    byte[] challenge = new byte[16];
                                    RANDOM.nextBytes(challenge);
                                    KeyPair keyPair = mc.server.getServerKeyPair();
                                    ChannelInboundHandlerAdapter handler =
                                            new ChannelInboundHandlerAdapter() {
                                                boolean encrypted;

                                                @Override
                                                public void channelRead(
                                                        ChannelHandlerContext ctx, Object message) {
                                                    try {
                                                        if (!encrypted
                                                                && message
                                                                        instanceof
                                                                        EncryptionResponsePacket
                                                                                response) {
                                                            if (!MessageDigest.isEqual(
                                                                    challenge,
                                                                    EncryptionUtils.decryptRsa(
                                                                            keyPair,
                                                                            response
                                                                                    .getVerifyToken())))
                                                                throw new GeneralSecurityException(
                                                                        "Wrong encryption"
                                                                            + " challenge");
                                                            byte[] secret =
                                                                    EncryptionUtils.decryptRsa(
                                                                            keyPair,
                                                                            response
                                                                                    .getSharedSecret());
                                                            if (secret.length != 16)
                                                                throw new GeneralSecurityException(
                                                                        "Invalid shared key");
                                                            mc.enableEncryption(secret);
                                                            encrypted = true;
                                                            if (authenticate) {
                                                                result.complete(EncryptionUtils.generateServerId(secret, keyPair.getPublic())
                                                                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                                                                return;
                                                            }
                                                            mc.write(
                                                                    new ClientboundCookieRequestPacket(
                                                                            COOKIE));
                                                        } else if (encrypted
                                                                && message
                                                                        instanceof
                                                                        ServerboundCookieResponsePacket
                                                                                response
                                                                && COOKIE.equals(
                                                                        response.getKey())) {
                                                            byte[] ticket = response.getPayload();
                                                            if (ticket == null
                                                                    || ticket.length
                                                                            != HandoffProtocol
                                                                                    .TICKET_LENGTH)
                                                                throw new GeneralSecurityException(
                                                                        "Missing transfer cookie");
                                                            result.complete(ticket.clone());
                                                        } else
                                                            throw new GeneralSecurityException(
                                                                    "Unexpected transfer login"
                                                                        + " packet");
                                                    } catch (Exception e) {
                                                        result.completeExceptionally(e);
                                                    } finally {
                                                        ReferenceCountUtil.release(message);
                                                    }
                                                }

                                                @Override
                                                public void channelInactive(
                                                        ChannelHandlerContext ctx)
                                                        throws Exception {
                                                    result.completeExceptionally(
                                                            new IllegalStateException(
                                                                    "Client disconnected"));
                                                    super.channelInactive(ctx);
                                                }

                                                @Override
                                                public void exceptionCaught(
                                                        ChannelHandlerContext ctx,
                                                        Throwable cause) {
                                                    result.completeExceptionally(cause);
                                                }
                                            };
                                    pipeline.addBefore(pipeline.context(mc).name(), name, handler);
                                    ScheduledFuture<?> timeout =
                                            mc.eventLoop()
                                                    .schedule(
                                                            () ->
                                                                    result.completeExceptionally(
                                                                            new TimeoutException(
                                                                                    "Transfer"
                                                                                        + " cookie"
                                                                                        + " timeout")),
                                                            timeoutMillis,
                                                            TimeUnit.MILLISECONDS);
                                    result.whenComplete(
                                            (value, failure) ->
                                                    mc.eventLoop()
                                                            .execute(
                                                                    () -> {
                                                                        timeout.cancel(false);
                                                                        if (pipeline.context(
                                                                                        handler)
                                                                                != null)
                                                                            pipeline.remove(
                                                                                    handler);
                                                                        if (failure != null)
                                                                            mc.close();
                                                                    }));
                                    EncryptionRequestPacket request = new EncryptionRequestPacket();
                                    request.setPublicKey(keyPair.getPublic().getEncoded());
                                    request.setVerifyToken(challenge);
                                    authenticateField.setBoolean(request, authenticate);
                                    mc.write(request);
                                } catch (Exception e) {
                                    result.completeExceptionally(e);
                                    mc.close();
                                }
                            });
        } catch (Exception e) {
            result.completeExceptionally(e);
        }
        return result;
    }
}
