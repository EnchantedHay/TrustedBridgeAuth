package top.pkumc.trustedbridgeauth;

import java.io.IOException;
import java.util.*;

/** Bounded, atomic single-use tickets. Used entries remain until their signed expiry. */
final class TicketStore {
    private record Entry(HandoffProtocol.Decoded handoff, byte[] signature, boolean used) {}

    private final Map<String, Entry> entries = new HashMap<>();
    private final int capacity;

    TicketStore(int capacity) {
        this.capacity = capacity;
    }

    synchronized void register(HandoffProtocol.Decoded handoff, byte[] signature, long now)
            throws IOException {
        cleanup(now);
        if (handoff.expiresAt() <= now) throw new IOException("Expired ticket");
        Entry old = entries.get(handoff.ticketHash());
        if (old != null) {
            // Identical pending registrations remain idempotent until the ticket is consumed.
            if (!old.used() && Arrays.equals(old.signature(), signature)) return;
            throw new IOException("Replayed ticket");
        }
        if (entries.size() >= capacity) throw new IOException("Ticket capacity reached");
        entries.put(handoff.ticketHash(), new Entry(handoff, signature.clone(), false));
    }

    synchronized HandoffProtocol.Decoded consume(byte[] ticket, String username, long now)
            throws IOException {
        cleanup(now);
        if (ticket == null || ticket.length != HandoffProtocol.TICKET_LENGTH)
            throw new IOException("Missing ticket");
        String hash = HexFormat.of().formatHex(HandoffProtocol.ticketHash(ticket));
        Entry entry = entries.get(hash);
        if (entry == null || entry.used() || !entry.handoff().profile().getName().equals(username))
            throw new IOException("Invalid, expired, used, or mismatched ticket");
        entries.put(hash, new Entry(entry.handoff(), entry.signature(), true));
        return entry.handoff();
    }

    synchronized void cleanup(long now) {
        entries.values().removeIf(e -> e.handoff().expiresAt() <= now);
    }
}
