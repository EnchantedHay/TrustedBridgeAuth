package top.pkumc.trustedbridgeauth;

import com.velocitypowered.api.util.GameProfile;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.zip.InflaterInputStream;

import javax.crypto.*;
import javax.crypto.spec.*;

/** Synthetic encrypted-login checks for a dedicated test Velocity instance. */
public final class LoginIntegrationTest {
    static byte[] secret;
    static int passed;
    static int protocol = 766;
    static String controlHost = "127.0.0.1", gameHost = "127.0.0.1";
    static int controlPort = 32566, gamePort = 32565;
    static String issuer = "pkumc", audience = "thunion";
    static BridgeLink link;
    static final UUID SOURCE_ID = UUID.fromString("00000000-0000-4000-8000-000000000001");
    static final UUID PREMIUM_ID = UUID.fromString("00000000-0000-4000-8000-000000000002");

    static void require(boolean b, String label) {
        if (!b) throw new AssertionError(label);
        passed++;
        System.out.println(java.time.Instant.now() + " PASS " + label);
    }

    static void varint(OutputStream out, int n) throws IOException {
        do {
            int b = n & 127;
            n >>>= 7;
            out.write(b | (n == 0 ? 0 : 128));
        } while (n != 0);
    }

    static int varint(InputStream in) throws IOException {
        int n = 0;
        for (int i = 0; i < 5; i++) {
            int b = in.read();
            if (b < 0) throw new EOFException();
            n |= (b & 127) << (7 * i);
            if ((b & 128) == 0) return n;
        }
        throw new IOException("Bad VarInt");
    }

    static void string(OutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        varint(out, b.length);
        out.write(b);
    }

    static String string(InputStream in) throws IOException {
        return new String(in.readNBytes(varint(in)), java.nio.charset.StandardCharsets.UTF_8);
    }

    static void array(OutputStream out, byte[] b) throws IOException {
        varint(out, b.length);
        out.write(b);
    }

    static byte[] array(InputStream in) throws IOException {
        return in.readNBytes(varint(in));
    }

    static byte[] ticket() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return b;
    }

    static void register(byte[] ticket) throws Exception {
        long now = System.currentTimeMillis();
        HandoffProtocol.Frame frame =
                HandoffProtocol.encode(
                        new GameProfile(SOURCE_ID, "AuditUser", List.of()),
                        "AuditUser", new GameProfile(PREMIUM_ID, "PremiumUser", List.of()),
                        SOURCE_ID, "legacy",
                        issuer,
                        audience,
                        now,
                        now + 30000,
                        HandoffProtocol.ticketHash(ticket),
                        secret);
        link.send(frame);
        require(true, "signed control ACK over mutual TLS");
    }

    static class Client implements AutoCloseable {
        final Socket socket = new Socket(gameHost, gamePort);
        InputStream in;
        OutputStream out;
        boolean compressed;

        Client(int intent) throws Exception {
            socket.setSoTimeout(7000);
            socket.setTcpNoDelay(true);
            in = socket.getInputStream();
            out = socket.getOutputStream();
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            varint(b, 0);
            varint(b, protocol);
            string(b, "localhost");
            new DataOutputStream(b).writeShort(gamePort);
            varint(b, intent);
            send(b.toByteArray());
            b.reset();
            varint(b, 0);
            string(b, "AuditUser");
            DataOutputStream d = new DataOutputStream(b);
            UUID clientId = UUID.randomUUID();
            d.writeLong(clientId.getMostSignificantBits());
            d.writeLong(clientId.getLeastSignificantBits());
            send(b.toByteArray());
        }

        void send(byte[] b) throws IOException {
            ByteArrayOutputStream packet = new ByteArrayOutputStream();
            varint(packet, b.length);
            packet.write(b);
            out.write(packet.toByteArray());
            out.flush();
        }

        DataInputStream read() throws IOException {
            byte[] b = in.readNBytes(varint(in));
            InputStream data = new ByteArrayInputStream(b);
            if (compressed) {
                int size = varint(data);
                if (size > 0) data = new InflaterInputStream(data);
            }
            return new DataInputStream(data);
        }

        void encryptedCookie(byte[] ticket) throws Exception {
            encryption(false);
            DataInputStream p = read();
            require(varint(p) == 5, "encrypted cookie request received");
            require(string(p).equals("pkumc:trusted_bridge_v2"), "private cookie namespace");
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            varint(response, 4);
            string(response, "pkumc:trusted_bridge_v2");
            response.write(ticket == null ? 0 : 1);
            if (ticket != null) array(response, ticket);
            send(response.toByteArray());
        }

        void encryption(boolean authenticate) throws Exception {
            DataInputStream p = read();
            require(varint(p) == 1, "encryption requested before cookie");
            string(p);
            byte[] pub = array(p), challenge = array(p);
            require(p.readBoolean() == authenticate, "encryption authentication flag matches login purpose");
            PublicKey key =
                    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, key);
            byte[] aes = new byte[16];
            new SecureRandom().nextBytes(aes);
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            varint(response, 1);
            array(response, rsa.doFinal(aes));
            array(response, rsa.doFinal(challenge));
            send(response.toByteArray());
            SecretKeySpec sk = new SecretKeySpec(aes, "AES");
            InputStream rawIn = in;
            OutputStream rawOut = out;
            // Explicit byte-stream CFB8 avoids CipherInputStream buffering short protocol frames.
            Cipher block = Cipher.getInstance("AES/ECB/NoPadding");
            block.init(Cipher.ENCRYPT_MODE, sk);
            byte[] readState = aes.clone(), writeState = aes.clone();
            in =
                    new InputStream() {
                        public int read() throws IOException {
                            int c = rawIn.read();
                            if (c < 0) return -1;
                            try {
                                int plain = c ^ (block.doFinal(readState)[0] & 255);
                                System.arraycopy(readState, 1, readState, 0, 15);
                                readState[15] = (byte) c;
                                return plain;
                            } catch (GeneralSecurityException e) {
                                throw new IOException(e);
                            }
                        }
                    };
            out =
                    new OutputStream() {
                        public void write(int plain) throws IOException {
                            try {
                                int c = (plain & 255) ^ (block.doFinal(writeState)[0] & 255);
                                System.arraycopy(writeState, 1, writeState, 0, 15);
                                writeState[15] = (byte) c;
                                rawOut.write(c);
                            } catch (GeneralSecurityException e) {
                                throw new IOException(e);
                            }
                        }

                        public void flush() throws IOException {
                            rawOut.flush();
                        }
                    };
        }

        boolean loginSuccess() throws Exception {
            try {
                for (int i = 0; i < 4; i++) {
                    DataInputStream p = read();
                    int id = varint(p);
                    if (id == 3) {
                        varint(p);
                        compressed = true;
                        continue;
                    }
                    if (id == 0) return false;
                    if (id == 2) {
                        UUID uuid = new UUID(p.readLong(), p.readLong());
                        String name = string(p);
                        require(
                                uuid.equals(PREMIUM_ID),
                                "premium UUID restored despite different LoginStart and source UUID");
                        require(name.equals("PremiumUser"), "premium name differs from client login name");
                        return true;
                    }
                    throw new IOException("Unexpected login packet " + id);
                }
            } catch (EOFException | SocketException e) {
                return false;
            }
            return false;
        }

        public void close() throws IOException {
            socket.close();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 1) protocol = Integer.parseInt(args[1]);
        if (args.length > 2) {
            controlHost = args[2];
            controlPort = Integer.parseInt(args[3]);
            gameHost = args[4];
            gamePort = Integer.parseInt(args[5]);
            issuer = args[6];
            audience = args[7];
        }
        secret = HexFormat.of().parseHex(Files.readString(Path.of(args[0])).trim());
        BridgeConfig cfg =
                new BridgeConfig(
                        issuer,
                        audience,
                        controlHost,
                        controlPort,
                        "connect",
                        gameHost,
                        gamePort,
                        "127.0.0.1",
                        5000,
                        30000,
                        secret,
                        "source",
                        Map.of(),
                        Path.of(args[8]));
        try (BridgeLink connection =
                new BridgeLink(
                        cfg,
                        frame -> HandoffProtocol.acknowledgement(frame, secret),
                        org.slf4j.LoggerFactory.getLogger("LoginIntegrationTest"))) {
            link = connection;
            link.start();
            BridgeLinkTest.await(link::connected);
            byte[] ticket = ticket();
            register(ticket);
            try (Client ordinary = new Client(2)) {
                DataInputStream p = ordinary.read();
                require(varint(p) == 1, "ordinary login requires encryption/auth");
                string(p);
                array(p);
                array(p);
                require(p.readBoolean(), "ordinary login remains online authenticated");
            }
            Thread.sleep(3100);
            try (Client missing = new Client(3)) {
                missing.encryptedCookie(null);
                require(!missing.loginSuccess(), "missing cookie rejected");
            }
            Thread.sleep(3100);
            try (Client valid = new Client(3)) {
                valid.encryptedCookie(ticket);
                require(valid.loginSuccess(), "valid transfer reaches login success");
            }
            Thread.sleep(3100);
            try (Client replay = new Client(3)) {
                replay.encryptedCookie(ticket);
                require(!replay.loginSuccess(), "used cookie rejected");
            }
            System.out.println("PASS: " + passed + " live-protocol assertions on isolated proxy");
        }
    }
}
