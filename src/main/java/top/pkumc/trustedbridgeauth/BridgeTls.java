package top.pkumc.trustedbridgeauth;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.net.ssl.*;

/** Mutual TLS identities authenticated by exact peer certificate pins and validity dates. */
final class BridgeTls {
    static SSLContext context(Path directory) throws IOException, GeneralSecurityException {
        char[] password =
                Files.readString(directory.resolve("store.password")).trim().toCharArray();
        try {
            KeyStore identity = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(directory.resolve("identity.p12"))) {
                identity.load(in, password);
            }
            KeyManagerFactory keys =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(identity, password);
            X509Certificate peer;
            try (InputStream in = Files.newInputStream(directory.resolve("peer.crt"))) {
                peer =
                        (X509Certificate)
                                CertificateFactory.getInstance("X.509").generateCertificate(in);
            }
            peer.checkValidity();
            X509TrustManager pin =
                    new X509TrustManager() {
                        private void check(X509Certificate[] chain) throws CertificateException {
                            if (chain == null
                                    || chain.length == 0
                                    || !MessageDigest.isEqual(
                                            chain[0].getEncoded(), peer.getEncoded()))
                                throw new CertificateException(
                                        "Unrecognized bridge peer certificate");
                            chain[0].checkValidity();
                        }

                        public void checkClientTrusted(X509Certificate[] chain, String auth)
                                throws CertificateException {
                            check(chain);
                        }

                        public void checkServerTrusted(X509Certificate[] chain, String auth)
                                throws CertificateException {
                            check(chain);
                        }

                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[] {peer};
                        }
                    };
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keys.getKeyManagers(), new TrustManager[] {pin}, new SecureRandom());
            return context;
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
