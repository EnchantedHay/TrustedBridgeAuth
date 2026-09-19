package top.pkumc.trustedbridgeauth;

import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;

/** Exercises the real encrypted binding login, with a loopback HTTPS identity fixture. */
public final class PremiumBindingIntegrationTest {
    public static void main(String[] args) throws Exception {
        try (LoginIntegrationTest.Client client = new LoginIntegrationTest.Client(2)) {
            client.encryption(true);
            DataInputStream packet = client.read();
            LoginIntegrationTest.require(LoginIntegrationTest.varint(packet) == 0,
                    "binding ends with encrypted disconnect, never game login");
            String message = new String(packet.readAllBytes(), StandardCharsets.UTF_8);
            LoginIntegrationTest.require(message.contains("012345"),
                    "verified binding code delivered to the encrypted client");
        }
    }
}
