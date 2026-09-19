package top.pkumc.trustedbridgeauth;

import java.nio.file.Path;
import java.util.UUID;

/** Read-only checks against the configured production identity authority. */
public final class PremiumApiSmokeTest {
    public static void main(String[] args) throws Exception {
        try (PremiumIdentityClient api = new PremiumIdentityClient(Path.of(args[0]), 10000)) {
            if (api.bindingCandidate(UUID.fromString("00000000-0000-4000-8000-000000000000"), "AuditUser"))
                throw new AssertionError("Unexpected binding candidate");
            System.out.println("PASS: authenticated HTTPS identity API reachable; unknown candidate denied");
            for (boolean outbound : new boolean[] {true, false}) {
                try {
                    api.resolve(UUID.fromString("00000000-0000-4000-8000-000000000000"), outbound, null);
                    throw new AssertionError("Unknown identity accepted");
                } catch (TransferFailure e) {
                    var expected = outbound ? TransferFailure.Reason.LOCAL_ACCOUNT_MISSING : TransferFailure.Reason.BINDING_REQUIRED;
                    if (e.reason != expected) throw new AssertionError("Wrong API rejection: " + e.reason);
                    System.out.println("PASS: live identity error mapped to " + expected);
                }
            }
            if (args.length > 1) {
                UUID local = UUID.fromString(args[1]);
                var outbound = api.resolve(local, true, null);
                var inbound = api.resolve(outbound.premium().getId(), false, local);
                if (!inbound.local().getId().equals(local)) throw new AssertionError("Return changed local UUID");
                System.out.println("PASS: live binding resolves premium profile and restores original local UUID; assurance="
                        + outbound.assurance());
            }
        }
    }
}
