package top.pkumc.trustedbridgeauth;

import org.slf4j.Logger;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import javax.net.ssl.*;

/** One authenticated duplex TLS connection; ACKs, bounded queues, heartbeat and reconnect. */
final class BridgeLink implements AutoCloseable {
    interface Receiver {
        byte[] receive(HandoffProtocol.Frame frame) throws IOException;
    }

    private static final int MAGIC = 0x54424c34;
    private final BridgeConfig config;
    private final Receiver receiver;
    private final BridgeStatus status;
    private final SSLContext tls;
    private final ScheduledThreadPoolExecutor clock =
            new ScheduledThreadPoolExecutor(
                    1, Thread.ofPlatform().daemon().name("bridge-link-clock").factory());
    private final ExecutorService tasks = Executors.newVirtualThreadPerTaskExecutor();
    private final Semaphore handshakes = new Semaphore(4);
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final AtomicReference<Session> active = new AtomicReference<>();
    private volatile boolean running;
    private volatile SSLServerSocket listener;

    BridgeLink(BridgeConfig config, Receiver receiver, Logger logger)
            throws IOException, GeneralSecurityException {
        this.config = config;
        this.receiver = receiver;
        this.status = new BridgeStatus(logger, config.peer());
        tls = BridgeTls.context(config.tlsDirectory());
        clock.setRemoveOnCancelPolicy(true);
    }

    void start() throws IOException {
        if (config.role().equals("listen")) {
            listener = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket();
            listener.setReuseAddress(true);
            listener.setEnabledProtocols(new String[] {"TLSv1.3"});
            listener.setNeedClientAuth(true);
            listener.bind(new InetSocketAddress(config.listenAddress(), config.bridgePort()), 16);
        }
        running = true;
        clock.scheduleAtFixedRate(
                () -> {
                    Session session = active.get();
                    if (session != null) session.enqueue(new Packet(3, 0, new byte[0]));
                },
                5,
                5,
                TimeUnit.SECONDS);
        tasks.submit(config.role().equals("listen") ? this::accept : this::connect);
    }

    boolean connected() {
        return active.get() != null;
    }

    void send(HandoffProtocol.Frame frame) throws IOException {
        Session session = active.get();
        if (session == null) throw new IOException("Bridge peer disconnected");
        session.send(frame);
    }

    private void accept() {
        while (running) {
            try {
                SSLSocket socket = (SSLSocket) listener.accept();
                if (!handshakes.tryAcquire()) {
                    closeSocket(socket);
                    continue;
                }
                sockets.add(socket);
                try {
                    tasks.submit(
                            () -> {
                                try {
                                    serve(socket);
                                } finally {
                                    handshakes.release();
                                }
                            });
                } catch (RejectedExecutionException e) {
                    sockets.remove(socket);
                    closeSocket(socket);
                    handshakes.release();
                    throw e;
                }
            } catch (IOException | RejectedExecutionException e) {
                if (!running) break;
                status.failed(e);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private void connect() {
        int backoff = 1;
        while (running) {
            try {
                SSLSocket socket = (SSLSocket) tls.getSocketFactory().createSocket();
                sockets.add(socket);
                try {
                    socket.connect(
                            new InetSocketAddress(config.peerHost(), config.bridgePort()),
                            config.timeoutMillis());
                    if (serve(socket)) backoff = 1;
                } finally {
                    sockets.remove(socket);
                    closeSocket(socket);
                }
            } catch (IOException e) {
                if (running) status.failed(e);
            }
            if (!running) break;
            try {
                Thread.sleep(backoff * 1000L + ThreadLocalRandom.current().nextInt(250));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            backoff = Math.min(10, backoff * 2);
        }
    }

    private boolean serve(SSLSocket socket) {
        Session session = null;
        long establishedAt = 0;
        ScheduledFuture<?> deadline = null;
        try {
            deadline =
                    clock.schedule(
                            () -> closeSocket(socket),
                            config.timeoutMillis(),
                            TimeUnit.MILLISECONDS);
            socket.setEnabledProtocols(new String[] {"TLSv1.3"});
            socket.setSoTimeout(config.timeoutMillis());
            socket.setTcpNoDelay(true);
            socket.startHandshake();
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
            out.writeInt(MAGIC);
            out.writeUTF(config.network());
            out.writeUTF(config.peer());
            out.flush();
            if (in.readInt() != MAGIC
                    || !readName(in).equals(config.peer())
                    || !readName(in).equals(config.network()))
                throw new IOException("Wrong link version or peer identity");
            session = new Session(socket, in, out);
            deadline.cancel(false);
            socket.setSoTimeout(15000);
            synchronized (status) {
                if (!running) throw new IOException("Bridge stopping");
                if (!active.compareAndSet(null, session))
                    throw new IOException("Peer already connected");
                establishedAt = System.nanoTime();
                status.connected(config.network());
            }
            Session established = session;
            tasks.submit(established::writeLoop);
            session.readLoop();
        } catch (IOException | RuntimeException e) {
            if (session != null && establishedAt != 0) session.closeWithCause(e);
            else if (running) status.failed(e);
        } finally {
            if (deadline != null) deadline.cancel(false);
            if (session != null) session.close();
            sockets.remove(socket);
            closeSocket(socket);
        }
        return establishedAt != 0
                && System.nanoTime() - establishedAt >= TimeUnit.SECONDS.toNanos(30);
    }

    private static String readName(DataInputStream in) throws IOException {
        int size = in.readUnsignedShort();
        if (size < 1 || size > 32) throw new IOException("Invalid network identity length");
        return new String(read(in, size), java.nio.charset.StandardCharsets.US_ASCII);
    }

    private record Packet(int type, long id, byte[] body) {}

    private final class Session {
        final SSLSocket socket;
        final DataInputStream in;
        final DataOutputStream out;
        final ArrayBlockingQueue<Packet> outbound = new ArrayBlockingQueue<>(128);
        final ConcurrentMap<Long, CompletableFuture<byte[]>> pending = new ConcurrentHashMap<>();
        final Semaphore slots = new Semaphore(64);
        final AtomicLong sequence = new AtomicLong();
        final AtomicBoolean closed = new AtomicBoolean();

        Session(SSLSocket socket, DataInputStream in, DataOutputStream out) {
            this.socket = socket;
            this.in = in;
            this.out = out;
        }

        void enqueue(Packet packet) {
            if (!closed.get() && !outbound.offer(packet))
                closeWithCause(new IOException("Outbound queue full"));
        }

        void send(HandoffProtocol.Frame frame) throws IOException {
            if (frame.payload().length == 0
                    || frame.payload().length > HandoffProtocol.MAX_FRAME_SIZE
                    || frame.mac().length != HandoffProtocol.MAC_LENGTH)
                throw new IOException("Invalid outbound handoff size");
            if (!slots.tryAcquire()) throw new TransferFailure(TransferFailure.Reason.BUSY);
            long id = sequence.incrementAndGet();
            CompletableFuture<byte[]> result = new CompletableFuture<>();
            try {
                pending.put(id, result);
                if (closed.get()) throw new IOException("Link closed");
                ByteArrayOutputStream buffer =
                        new ByteArrayOutputStream(frame.payload().length + frame.mac().length);
                buffer.write(frame.payload());
                buffer.write(frame.mac());
                enqueue(new Packet(1, id, buffer.toByteArray()));
                byte[] ack = result.get(config.timeoutMillis(), TimeUnit.MILLISECONDS);
                if (!MessageDigest.isEqual(
                        ack, HandoffProtocol.acknowledgement(frame, config.secret()))) {
                    IOException failure = new IOException("Invalid handoff acknowledgement");
                    closeWithCause(failure);
                    throw failure;
                }
            } catch (ExecutionException e) {
                if (e.getCause() instanceof TransferFailure rejection) throw rejection;
                closeWithCause(e);
                throw new IOException("Handoff not acknowledged", e);
            } catch (TimeoutException e) {
                closeWithCause(new SocketTimeoutException("Handoff acknowledgement timed out"));
                throw new IOException("Handoff not acknowledged", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                close();
                throw new IOException("Interrupted", e);
            } finally {
                pending.remove(id);
                slots.release();
            }
        }

        void readLoop() throws IOException {
            while (!closed.get()) {
                int type = in.readUnsignedByte();
                long id;
                int size;
                byte[] body;
                // SO_TIMEOUT alone can be kept alive indefinitely by a trickle of bytes.
                ScheduledFuture<?> deadline = clock.schedule(
                        () -> closeWithCause(new SocketTimeoutException("Link frame read timed out")),
                        config.timeoutMillis(), TimeUnit.MILLISECONDS);
                try {
                    id = in.readLong();
                    size = in.readInt();
                    boolean valid = switch (type) {
                        case 1 -> id > 0 && size > HandoffProtocol.MAC_LENGTH
                                && size <= HandoffProtocol.MAX_FRAME_SIZE + HandoffProtocol.MAC_LENGTH;
                        case 2 -> id > 0 && size == HandoffProtocol.MAC_LENGTH;
                        case 3 -> id == 0 && size == 0;
                        case 4 -> id > 0 && size == 1;
                        default -> false;
                    };
                    if (!valid) throw new IOException("Invalid link message header");
                    body = read(in, size);
                } finally {
                    deadline.cancel(false);
                }
                if (type == 1 && id > 0 && size > HandoffProtocol.MAC_LENGTH) {
                    int split = size - HandoffProtocol.MAC_LENGTH;
                    HandoffProtocol.Frame frame =
                            new HandoffProtocol.Frame(
                                    java.util.Arrays.copyOf(body, split),
                                    java.util.Arrays.copyOfRange(body, split, size));
                    try {
                        enqueue(new Packet(2, id, receiver.receive(frame)));
                    } catch (IOException e) {
                        TransferFailure.Reason reason = e instanceof TransferFailure failure
                                ? failure.reason : TransferFailure.Reason.REJECTED;
                        enqueue(new Packet(4, id, new byte[] {(byte) reason.ordinal()}));
                    }
                } else if (type == 2 && size == HandoffProtocol.MAC_LENGTH) {
                    CompletableFuture<byte[]> result = pending.get(id);
                    if (result != null) result.complete(body);
                } else if (type == 4 && size == 1) {
                    CompletableFuture<byte[]> result = pending.get(id);
                    if (result != null)
                        result.completeExceptionally(new TransferFailure(TransferFailure.decode(Byte.toUnsignedInt(body[0]))));
                } else if (type != 3 || id != 0 || size != 0)
                    throw new IOException("Invalid link message");
            }
        }

        void writeLoop() {
            try {
                while (!closed.get()) {
                    Packet packet = outbound.poll(1, TimeUnit.SECONDS);
                    if (packet == null) continue;
                    ScheduledFuture<?> deadline =
                            clock.schedule(
                                    () -> closeWithCause(new SocketTimeoutException("Link write timed out")),
                                    config.timeoutMillis(), TimeUnit.MILLISECONDS);
                    try {
                        out.writeByte(packet.type());
                        out.writeLong(packet.id());
                        out.writeInt(packet.body().length);
                        out.write(packet.body());
                        out.flush();
                    } finally {
                        deadline.cancel(false);
                    }
                }
            } catch (IOException | InterruptedException | RuntimeException e) {
                closeWithCause(e);
            }
        }

        void close() {
            closeWithCause(new IOException("Link closed or timed out"));
        }

        void closeWithCause(Throwable reason) {
            if (!closed.compareAndSet(false, true)) return;
            synchronized (status) {
                if (active.compareAndSet(this, null) && running)
                    status.disconnected(reason);
            }
            pending.values()
                    .forEach(
                            future ->
                                    future.completeExceptionally(
                                            new IOException("Link disconnected")));
            outbound.clear();
            closeSocket(socket);
        }
    }

    private static byte[] read(DataInputStream in, int size) throws IOException {
        byte[] bytes = in.readNBytes(size);
        if (bytes.length != size) throw new EOFException();
        return bytes;
    }

    private static void closeSocket(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    public void close() {
        running = false;
        try {
            if (listener != null) listener.close();
        } catch (IOException ignored) {
        }
        Session session = active.get();
        if (session != null) session.close();
        sockets.forEach(BridgeLink::closeSocket);
        tasks.shutdownNow();
        clock.shutdownNow();
    }
}
