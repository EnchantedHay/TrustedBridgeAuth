package top.pkumc.trustedbridgeauth;

import com.google.gson.*;
import com.velocitypowered.api.util.GameProfile;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;

/** The skin site's binding authority is reached only over authenticated HTTPS. */
final class PremiumIdentityClient implements AutoCloseable {
    private final URI base;
    private final String token;
    private final HttpClient http;
    private final int timeout;

    PremiumIdentityClient(Path directory, int timeout) throws IOException {
        Properties p = new Properties();
        try (Reader reader = Files.newBufferedReader(directory.resolve("config.properties"))) {
            p.load(reader);
        }
        try {
            base = URI.create(p.getProperty("skin-api-url", ""));
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid skin-api-url", e);
        }
        if (!"https".equals(base.getScheme()) || base.getHost() == null
                || base.getUserInfo() != null || base.getQuery() != null || base.getFragment() != null
                || !base.getPath().endsWith("/")) throw new IOException("skin-api-url must be HTTPS and end in /");
        token = Files.readString(directory.resolve(p.getProperty("skin-api-secret-file", "skin-api.secret"))).trim();
        if (!token.matches("[a-fA-F0-9]{64}")) throw new IOException("Invalid skin API key");
        this.timeout = timeout;
        http = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(timeout))
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    JsonObject post(String path, JsonObject body) throws IOException {
        HttpRequest request = HttpRequest.newBuilder(base.resolve(path))
                .timeout(Duration.ofMillis(timeout)).header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build();
        try {
            HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
                byte[] bytes = response.body();
                if (bytes.length > 32768) throw new IOException("Oversized skin identity response");
                if (response.statusCode() != 200) {
                    TransferFailure.Reason reason = TransferFailure.Reason.IDENTITY_UNAVAILABLE;
                    if (path.equals("resolve")) {
                        try {
                            String code = JsonParser.parseString(new String(bytes, java.nio.charset.StandardCharsets.UTF_8))
                                    .getAsJsonObject().get("error").getAsString();
                            reason = switch (code) {
                                case "BINDING_REQUIRED" -> TransferFailure.Reason.BINDING_REQUIRED;
                                case "LOCAL_ACCOUNT_MISSING" -> TransferFailure.Reason.LOCAL_ACCOUNT_MISSING;
                                case "CHARACTER_REQUIRED" -> TransferFailure.Reason.CHARACTER_REQUIRED;
                                case "CHARACTER_AMBIGUOUS" -> TransferFailure.Reason.CHARACTER_AMBIGUOUS;
                                case "CHARACTER_CHANGED" -> TransferFailure.Reason.CHARACTER_CHANGED;
                                case "ACCOUNT_UNAVAILABLE" -> TransferFailure.Reason.ACCOUNT_UNAVAILABLE;
                                default -> TransferFailure.Reason.IDENTITY_UNAVAILABLE;
                            };
                        } catch (RuntimeException ignored) { }
                    }
                    throw new TransferFailure(reason);
                }
                return JsonParser.parseString(new String(bytes, java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Skin identity request interrupted", e);
        } catch (TransferFailure e) {
            throw e;
        } catch (IOException e) {
            throw new TransferFailure(TransferFailure.Reason.IDENTITY_UNAVAILABLE);
        } catch (RuntimeException e) {
            throw new IOException("Invalid skin identity response", e);
        }
    }

    boolean bindingCandidate(UUID id, String name) throws IOException {
        if (id == null) return false;
        JsonObject body = new JsonObject();
        body.addProperty("uuid", id.toString());
        body.addProperty("username", name);
        return post("candidate", body).get("candidate").getAsBoolean();
    }

    String verifyLogin(String name, String serverId) throws IOException {
        JsonObject body = new JsonObject();
        body.addProperty("username", name);
        body.addProperty("server_id", serverId);
        String code = post("verify-login", body).get("code").getAsString();
        if (!code.matches("[0-9]{6}")) throw new IOException("Invalid binding code");
        return code;
    }

    Identity resolve(UUID uuid, boolean outbound, UUID local) throws IOException {
        JsonObject body = new JsonObject();
        body.addProperty("direction", outbound ? "outbound" : "inbound");
        body.addProperty("uuid", uuid.toString());
        if (local != null) body.addProperty("local_uuid", local.toString());
        try {
            JsonObject response = post("resolve", body);
            Identity result = new Identity(profile(response.getAsJsonObject("local")),
                    profile(response.getAsJsonObject("premium")), response.get("assurance").getAsString());
            if (!(outbound ? result.local() : result.premium()).getId().equals(uuid)
                    || (local != null && !result.local().getId().equals(local))
                    || !Set.of("legacy", "login_code").contains(result.assurance()))
                throw new IOException("Mismatched identity response");
            return result;
        } catch (RuntimeException e) {
            throw new IOException("Invalid identity response", e);
        }
    }

    static GameProfile profile(JsonObject json) throws IOException {
        String raw = json.get("id").getAsString().replace("-", "");
        String name = json.get("name").getAsString();
        if (!raw.matches("[a-fA-F0-9]{32}") || !name.matches("[A-Za-z0-9_]{1,16}"))
            throw new IOException("Invalid profile");
        UUID id = UUID.fromString(raw.substring(0, 8) + "-" + raw.substring(8, 12) + "-"
                + raw.substring(12, 16) + "-" + raw.substring(16, 20) + "-" + raw.substring(20));
        List<GameProfile.Property> properties = new ArrayList<>();
        JsonArray entries = json.getAsJsonArray("properties");
        if (entries != null) for (JsonElement entry : entries) {
            JsonObject p = entry.getAsJsonObject();
            properties.add(new GameProfile.Property(p.get("name").getAsString(),
                    p.get("value").getAsString(), p.has("signature") ? p.get("signature").getAsString() : ""));
        }
        if (properties.size() > 16) throw new IOException("Too many profile properties");
        return new GameProfile(id, name, properties);
    }

    public void close() { http.shutdownNow(); }

    record Identity(GameProfile local, GameProfile premium, String assurance) {}
}
