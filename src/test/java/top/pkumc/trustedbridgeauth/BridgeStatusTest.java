package top.pkumc.trustedbridgeauth;

import org.slf4j.Logger;

import java.io.EOFException;
import java.lang.reflect.Proxy;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

public final class BridgeStatusTest {
    public static void main(String[] args) {
        List<String> messages = new ArrayList<>();
        List<String> argumentsSeen = new ArrayList<>();
        Logger logger = (Logger) Proxy.newProxyInstance(Logger.class.getClassLoader(),
                new Class<?>[] {Logger.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("warn") || method.getName().equals("info")) {
                        messages.add((String) arguments[0]);
                        argumentsSeen.add(java.util.Arrays.deepToString(arguments));
                    }
                    return null;
                });
        BridgeStatus status = new BridgeStatus(logger, "peer");
        status.failed(new ConnectException("Connection refused"));
        for (int i = 0; i < 100; i++) status.failed(new ConnectException("Connection refused"));
        require(messages.size() == 1, "startup failures are silent after first warning");
        status.failed(new SocketTimeoutException("Connect timed out"));
        status.failed(new ConnectException("Connection refused"));
        status.failed(new SocketTimeoutException("Connect timed out"));
        require(messages.size() == 2, "each distinct error is reported once per outage");
        status.connected("local");
        require(messages.get(2).startsWith("Bridge restored:"), "recovery is reported");
        status.disconnected(new EOFException());
        status.failed(new EOFException());
        require(messages.size() == 4 && messages.get(3).startsWith("Bridge disconnected:"),
                "disconnection reason is not repeated");
        status.failed(new ConnectException("Connection refused"));
        require(messages.size() == 5, "new outage resets error deduplication");
        status.connected("local");
        status.failed(new javax.net.ssl.SSLHandshakeException("Bad certificate"));
        status.disconnected(new EOFException());
        require(messages.get(7).startsWith("Bridge disconnected:"),
                "rejected extra connection does not change active link status");
        BridgeStatus bounded = new BridgeStatus(logger, "peer");
        messages.clear();
        for (int i = 0; i < 1000; i++) bounded.failed(new java.io.IOException("Failure " + i));
        require(messages.size() == 129, "error memory and warnings are bounded during an error flood");
        bounded.connected("local");
        bounded.disconnected(new EOFException());
        bounded.failed(new java.io.IOException("Failure 0"));
        require(messages.size() == 132, "recovery resets saturated error tracking");
        bounded.failed(new java.io.IOException("bad\r\n\u001b[31m" + "x".repeat(10000)));
        String logged = argumentsSeen.getLast();
        require(!logged.contains("\r") && !logged.contains("\n") && !logged.contains("\u001b")
                && logged.length() < 512, "error text cannot inject lines or unbounded output");
        System.out.println("PASS: bridge status logging checks");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
