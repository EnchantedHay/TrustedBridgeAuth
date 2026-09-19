package top.pkumc.trustedbridgeauth;

import com.velocitypowered.api.util.GameProfile;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Signed recipient-bound profiles with client ticket hashes and expiry times. */
final class HandoffProtocol {
    static final int MAC_LENGTH = 32;
    static final int MAX_FRAME_SIZE = 32 * 1024;
    static final int TICKET_LENGTH = 32;
    private static final int MAGIC = 0x54424134;
    private static final long CLOCK_SKEW = 5000;

    static byte[] ticketHash(byte[] ticket) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(ticket);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static Frame encode(
            GameProfile profile,
            String issuer,
            String audience,
            long issuedAt,
            long expiresAt,
            byte[] ticketHash,
            byte[] secret)
            throws IOException {
        return encode(profile, profile.getName(), null, null, "none", issuer, audience,
                issuedAt, expiresAt, ticketHash, secret);
    }

    static Frame encode(GameProfile profile, String loginName, GameProfile premium,
            UUID localUuid, String assurance, String issuer, String audience, long issuedAt,
            long expiresAt, byte[] ticketHash, byte[] secret) throws IOException {
        validateIdentity(loginName, premium, localUuid, assurance);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeInt(MAGIC);
            writeString(out, issuer);
            writeString(out, audience);
            out.writeLong(issuedAt);
            out.writeLong(expiresAt);
            if (ticketHash.length != 32) throw new IOException("Invalid ticket hash");
            out.write(ticketHash);
            writeString(out, loginName);
            writeString(out, assurance);
            writeString(out, localUuid == null ? "" : localUuid.toString());
            out.writeBoolean(premium != null);
            if (premium != null) writeProfile(out, premium);
            writeProfile(out, profile);
        }
        byte[] payload = bytes.toByteArray();
        if (payload.length > MAX_FRAME_SIZE) throw new IOException("Handoff too large");
        return new Frame(payload, hmac(payload, secret));
    }

    private static void writeProfile(DataOutputStream out, GameProfile profile) throws IOException {
            if (!profile.getName().matches("[A-Za-z0-9_]{1,16}")) throw new IOException("Invalid username");
            writeString(out, profile.getName());
            out.writeLong(profile.getId().getMostSignificantBits());
            out.writeLong(profile.getId().getLeastSignificantBits());
            if (profile.getProperties().size() > 16) throw new IOException("Too many properties");
            out.writeInt(profile.getProperties().size());
            for (GameProfile.Property p : profile.getProperties()) {
                writeString(out, p.getName());
                writeString(out, p.getValue());
                writeString(out, p.getSignature() == null ? "" : p.getSignature());
            }
    }

    static Decoded verifyAndDecode(
            byte[] payload,
            byte[] signature,
            byte[] secret,
            String issuer,
            String audience,
            long now,
            long maxTtl)
            throws IOException {
        if (payload.length > MAX_FRAME_SIZE
                || signature.length != MAC_LENGTH
                || !MessageDigest.isEqual(hmac(payload, secret), signature))
            throw new IOException("Invalid handoff signature or size");
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (in.readInt() != MAGIC) throw new IOException("Unsupported handoff protocol");
            if (!readString(in).equals(issuer) || !readString(in).equals(audience))
                throw new IOException("Wrong handoff issuer or audience");
            long issuedAt = in.readLong(), expiresAt = in.readLong();
            if (issuedAt > now + CLOCK_SKEW
                    || issuedAt < now - maxTtl
                    || expiresAt <= now
                    || expiresAt <= issuedAt
                    || expiresAt - issuedAt > maxTtl)
                throw new IOException("Invalid or expired handoff lifetime");
            byte[] hash = in.readNBytes(32);
            if (hash.length != 32) throw new EOFException();
            String loginName = readString(in), assurance = readString(in), local = readString(in);
            UUID localUuid;
            try {
                localUuid = local.isEmpty() ? null : UUID.fromString(local);
            } catch (IllegalArgumentException e) {
                throw new IOException("Invalid local identity", e);
            }
            GameProfile premium = in.readBoolean() ? readProfile(in) : null;
            validateIdentity(loginName, premium, localUuid, assurance);
            GameProfile profile = readProfile(in);
            if (in.available() != 0) throw new IOException("Trailing handoff data");
            return new Decoded(profile, HexFormat.of().formatHex(hash), expiresAt,
                    loginName, premium, localUuid, assurance);
        }
    }

    private static GameProfile readProfile(DataInputStream in) throws IOException {
            String name = readString(in);
            if (!name.matches("[A-Za-z0-9_]{1,16}")) throw new IOException("Invalid username");
            UUID uuid = new UUID(in.readLong(), in.readLong());
            int count = in.readInt();
            if (count < 0 || count > 16) throw new IOException("Invalid property count");
            List<GameProfile.Property> properties = new ArrayList<>();
            for (int i = 0; i < count; i++)
                properties.add(
                        new GameProfile.Property(readString(in), readString(in), readString(in)));
            return new GameProfile(uuid, name, properties);
    }

    private static void validateIdentity(String loginName, GameProfile premium, UUID localUuid,
            String assurance) throws IOException {
        if (!loginName.matches("[A-Za-z0-9_]{1,16}")
                || !Set.of("none", "legacy", "login_code", "session").contains(assurance)
                || ((premium == null) != assurance.equals("none"))
                || (premium == null && localUuid != null))
            throw new IOException("Invalid identity assertion");
    }

    static byte[] hmac(byte[] payload, byte[] secret) throws IOException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    // The acknowledgement authenticates the frame signature in a separate HMAC domain.
    static byte[] acknowledgement(Frame frame, byte[] secret) throws IOException {
        byte[] input = new byte[frame.mac().length + 1];
        input[0] = 1;
        System.arraycopy(frame.mac(), 0, input, 1, frame.mac().length);
        return hmac(input, secret);
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 16384) throw new IOException("String too long");
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readString(DataInputStream in) throws IOException {
        int size = in.readInt();
        if (size < 0 || size > 16384 || size > in.available())
            throw new IOException("Invalid string size");
        return new String(in.readNBytes(size), StandardCharsets.UTF_8);
    }

    record Frame(byte[] payload, byte[] mac) {}

    record Decoded(GameProfile profile, String ticketHash, long expiresAt, String loginName,
            GameProfile premium, UUID localUuid, String assurance) {
        Decoded withProfile(GameProfile target) {
            return new Decoded(target, ticketHash, expiresAt, loginName, premium, localUuid, assurance);
        }
    }
}
