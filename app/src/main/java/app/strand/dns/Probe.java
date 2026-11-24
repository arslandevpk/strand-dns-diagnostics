package app.strand.dns;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.zip.GZIPInputStream;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * On-device DoH and DoT. Opens the encrypted session from this process and sends one DNS query.
 * There is no relay.
 */
public final class Probe {
    private Probe() {}

    public static final class ProbeException extends RuntimeException {
        public final String code;

        public ProbeException(String message, String code) {
            super(message);
            this.code = code;
        }
    }

    private static final X509ExtendedTrustManager TRUST_ALL = new X509ExtendedTrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {}

        public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {}

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    public static Models.ProbeResult run(Models.CheckInput input) {
        long started = System.currentTimeMillis();
        String protocol = "dot".equals(input.protocol) ? "dot" : "doh";
        String qtype = Endpoints.isQType(input.qtype) ? input.qtype : "A";
        String endpointText = input.endpoint == null ? "" : input.endpoint.trim();
        String queryName = input.name == null ? "" : input.name.trim();
        int timeoutMs = clamp(input.timeoutMs, 1500, 12000);
        try {
            queryName = Endpoints.normalizeQueryName(input.name);
        } catch (RuntimeException error) {
            String message = error.getMessage() == null ? "That name isn't valid DNS." : error.getMessage();
            return Present.failure(protocol, qtype, endpointText, "", queryName, message, "name", 0, null);
        }
        Endpoints.Parsed parsed = Endpoints.parseEndpoint(endpointText, protocol);
        if (!parsed.ok) {
            return Present.failure(protocol, qtype, endpointText, "", queryName, parsed.error, "endpoint", 0, null);
        }
        try {
            if ("dot".equals(parsed.protocol)) return probeDot(parsed, input.strict, qtype, queryName, timeoutMs, started);
            return probeDoh(parsed, input.strict, qtype, queryName, timeoutMs, started);
        } catch (Exception error) {
            Present.Explained explained = Present.explain(error);
            String host = "doh".equals(parsed.protocol) ? parsed.host : parsed.connectHost;
            return Present.failure(protocol, qtype, parsed.endpoint, host, queryName, explained.message, explained.code, System.currentTimeMillis() - started, null);
        }
    }

    private static Models.ProbeResult probeDoh(Endpoints.Parsed parsed, boolean strict, String qtype, String queryName, int timeoutMs, long started) throws Exception {
        long deadline = started + timeoutMs;
        Resolved resolved = resolve(parsed.host);
        byte[] query = DnsCodec.encodeQuery(queryName, qtype);
        int id = DnsCodec.readId(query);
        String sni = Endpoints.isIp(parsed.host) ? null : parsed.host;
        Socket tcp = connect(resolved, 443, deadline);
        String address = tcp.getInetAddress().getHostAddress();
        SSLSocket ssl = null;
        long tcpAt = System.currentTimeMillis();
        long tlsAt = 0;
        try {
            ssl = handshake(tcp, address, sni, 443, strict, null, deadline);
            tlsAt = System.currentTimeMillis();
            String hostHeader = parsed.host.indexOf(':') >= 0 ? "[" + parsed.host + "]" : parsed.host;
            String head = "POST " + parsed.path + " HTTP/1.1\r\n"
                    + "Host: " + hostHeader + "\r\n"
                    + "Content-Type: application/dns-message\r\n"
                    + "Accept: application/dns-message\r\n"
                    + "Accept-Encoding: identity\r\n"
                    + "Content-Length: " + query.length + "\r\n"
                    + "Connection: close\r\n"
                    + "User-Agent: Strand/1.0\r\n"
                    + "\r\n";
            OutputStream out = ssl.getOutputStream();
            out.write(head.getBytes("ISO-8859-1"));
            out.write(query);
            out.flush();
            byte[] raw = readUntilClose(ssl.getInputStream(), deadline);
            Http http = parseHttp(raw);
            byte[] body = http.body;
            if (body.length >= 2 && (body[0] & 0xff) == 0x1f && (body[1] & 0xff) == 0x8b) body = gunzip(body);
            long done = System.currentTimeMillis();
            Models.DnsView dns = null;
            String dnsError = null;
            if (body.length >= 12) {
                try {
                    dns = DnsCodec.decodeMessage(body, id, queryName);
                } catch (DnsCodec.DnsParseError error) {
                    dnsError = error.getMessage();
                }
            } else if (http.status != 200) {
                dnsError = "The resolver returned HTTP " + (http.status == 0 ? "error" : String.valueOf(http.status)) + ".";
            } else {
                dnsError = "The resolver returned an empty body.";
            }
            Models.CertInfo cert = readCert(ssl, sni, strict);
            Models.Transport transport = transportOf(ssl, address, 443);
            transport.httpStatus = Integer.valueOf(http.status);
            transport.httpVersion = "HTTP/1.1";
            transport.contentType = http.contentType;
            boolean typeOk = http.contentType == null || http.contentType.indexOf("dns-message") >= 0;
            String exchange = join(" · ", "HTTP/1.1", http.status == 0 ? "no status" : String.valueOf(http.status), typeOk ? (http.contentType == null ? "dns-message" : http.contentType) : http.contentType, body.length + " bytes");
            return assemble(parsed.endpoint, parsed.host, "doh", qtype, queryName, strict, started, done, resolved, tcpAt, tlsAt, transport, cert, dns, dnsError, exchange, http.status != 0 && http.status != 200 && dns == null, "Queried from this device over HTTPS.");
        } finally {
            close(ssl);
            close(tcp);
        }
    }

    private static Models.ProbeResult probeDot(Endpoints.Parsed parsed, boolean strict, String qtype, String queryName, int timeoutMs, long started) throws Exception {
        long deadline = started + timeoutMs;
        Resolved resolved = resolve(parsed.connectHost);
        byte[] query = DnsCodec.encodeQuery(queryName, qtype);
        int id = DnsCodec.readId(query);
        String sni = parsed.servername != null && !Endpoints.isIp(parsed.servername)
                ? parsed.servername
                : (Endpoints.isIp(parsed.connectHost) ? null : parsed.connectHost);
        String host = parsed.servername != null && parsed.servername.length() > 0 ? parsed.servername : parsed.connectHost;
        Socket tcp = connect(resolved, parsed.port, deadline);
        String address = tcp.getInetAddress().getHostAddress();
        SSLSocket ssl = null;
        long tcpAt = System.currentTimeMillis();
        long tlsAt = 0;
        try {
            ssl = handshake(tcp, address, sni, parsed.port, strict, "dot", deadline);
            tlsAt = System.currentTimeMillis();
            OutputStream out = ssl.getOutputStream();
            byte[] frame = new byte[query.length + 2];
            frame[0] = (byte) (query.length >>> 8);
            frame[1] = (byte) query.length;
            System.arraycopy(query, 0, frame, 2, query.length);
            out.write(frame);
            out.flush();
            byte[] lenBuf = readExact(ssl.getInputStream(), 2, deadline);
            int len = ((lenBuf[0] & 0xff) << 8) | (lenBuf[1] & 0xff);
            if (len < 12 || len > 8192) throw new ProbeException("The DoT response length was invalid.", "malformed");
            byte[] body = readExact(ssl.getInputStream(), len, deadline);
            long done = System.currentTimeMillis();
            Models.DnsView dns = null;
            String dnsError = null;
            try {
                dns = DnsCodec.decodeMessage(body, id, queryName);
            } catch (DnsCodec.DnsParseError error) {
                dnsError = error.getMessage();
            }
            Models.CertInfo cert = readCert(ssl, sni, strict);
            Models.Transport transport = transportOf(ssl, address, parsed.port);
            return assemble(parsed.endpoint, host, "dot", qtype, queryName, strict, started, done, resolved, tcpAt, tlsAt, transport, cert, dns, dnsError, body.length + " byte DNS message over TLS", false, "Queried from this device over TLS on port 853.");
        } finally {
            close(ssl);
            close(tcp);
        }
    }

    private static Models.ProbeResult assemble(
            String endpoint,
            String host,
            String protocol,
            String qtype,
            String queryName,
            boolean strict,
            long started,
            long done,
            Resolved resolved,
            long tcpAt,
            long tlsAt,
            Models.Transport transport,
            Models.CertInfo cert,
            Models.DnsView dns,
            String dnsError,
            String exchangeDetail,
            boolean exchangeFailed,
            String note) {
        long lookupEnd = started + resolved.ms;
        Long tcpMs = tcpAt > 0 ? Long.valueOf(Math.max(0, tcpAt - lookupEnd)) : null;
        Long tlsMs = tlsAt > 0 ? Long.valueOf(Math.max(0, tlsAt - (tcpAt > 0 ? tcpAt : lookupEnd))) : null;
        long queryAnchor = tlsAt > 0 ? tlsAt : (tcpAt > 0 ? tcpAt : lookupEnd);
        Long queryMs = Long.valueOf(Math.max(0, done - queryAnchor));
        String tlsDetail = join(" · ", transport.tls == null ? "TLS" : transport.tls, transport.cipher, cert != null && cert.subject.length() > 0 ? cert.subject : null, cert != null ? cert.daysRemaining + "d left" : null, cert != null && !cert.authorized ? "not trusted" : null);
        int port = "dot".equals(protocol) ? 853 : 443;
        String verdict = Present.decideVerdict(dns, cert == null ? null : Boolean.valueOf(cert.authorized), strict);
        if (dns == null) verdict = "down";
        else if (transport.httpStatus != null && transport.httpStatus.intValue() != 200) verdict = "degraded";
        String summary = Present.summarize(dns, queryName, qtype, dnsError);
        if (transport.httpStatus != null && transport.httpStatus.intValue() != 200 && dns != null) {
            summary = "HTTP " + transport.httpStatus + ". " + summary;
        }
        Models.ProbeResult result = new Models.ProbeResult();
        result.source = "device";
        result.protocol = protocol;
        result.endpoint = endpoint;
        result.host = host;
        result.queryName = queryName;
        result.qtype = qtype;
        result.verdict = verdict;
        result.summary = summary;
        result.note = note;
        result.code = dns == null ? "dns" : null;
        result.timing = new Models.Timing(Math.max(0, done - started), Long.valueOf(resolved.ms), tcpMs, tlsMs, queryMs);
        result.transport = transport;
        result.certificate = cert;
        result.dns = dns;
        String remote = transport.remoteAddress;
        int remotePort = transport.remotePort != null ? transport.remotePort.intValue() : port;
        result.stages = Present.stages(
                Present.stage("resolve", "ok", host + " → " + remote, Long.valueOf(resolved.ms)),
                Present.stage("tcp", "ok", remote + ":" + remotePort, tcpMs),
                Present.stage("tls", "ok", tlsDetail, tlsMs),
                Present.stage("exchange", exchangeFailed ? "fail" : "ok", exchangeDetail, queryMs),
                dns != null
                        ? Present.stage("dns", dns.questionMatched ? "ok" : "fail", Present.dnsDetail(dns), null)
                        : Present.stage("dns", "fail", dnsError == null ? "No DNS message" : dnsError, null));
        result.checkedAt = Iso.now();
        return result;
    }

    private static final class Resolved {
        final InetAddress[] addresses;
        final long ms;

        Resolved(InetAddress[] addresses, long ms) {
            this.addresses = addresses;
            this.ms = ms;
        }
    }

    private static Resolved resolve(String host) {
        long started = System.nanoTime();
        if (Endpoints.isBlockedName(host)) throw new ProbeException("That hostname can't be checked.", "name");
        try {
            return new Resolved(InetAddress.getAllByName(host), (System.nanoTime() - started) / 1000000L);
        } catch (java.net.UnknownHostException error) {
            throw new ProbeException("The hostname did not resolve.", "ENOTFOUND");
        }
    }

    private static Socket connect(Resolved resolved, int port, long deadline) throws Exception {
        IOException lastError = null;
        for (int i = 0; i < resolved.addresses.length; i++) {
            int timeout = remaining(deadline);
            if (i + 1 < resolved.addresses.length) timeout = Math.min(timeout, 2000);
            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress(resolved.addresses[i], port), timeout);
                return socket;
            } catch (IOException error) {
                close(socket);
                lastError = error;
            }
        }
        if (lastError != null) throw lastError;
        throw new IOException("The hostname did not resolve.");
    }

    private static SSLSocket handshake(Socket tcp, String address, String sni, int port, boolean strict, String alpn, long deadline) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        if (strict) ctx.init(null, null, null);
        else ctx.init(null, new TrustManager[] {TRUST_ALL}, new SecureRandom());
        String peer = sni != null ? sni : address;
        SSLSocket ssl = (SSLSocket) ctx.getSocketFactory().createSocket(tcp, peer, port, true);
        ssl.setUseClientMode(true);
        SSLParameters params = ssl.getSSLParameters();
        if (sni != null && !Endpoints.isIp(sni)) {
            params.setServerNames(Collections.singletonList(new SNIHostName(sni)));
            try {
                ssl.getClass().getMethod("setHostname", String.class).invoke(ssl, sni);
            } catch (Throwable ignored) {
                // API 24 still gets SNI from SSLParameters. setHostname is the older Conscrypt hook.
            }
        }
        if (strict && peer != null && peer.length() > 0) params.setEndpointIdentificationAlgorithm("HTTPS");
        if (alpn != null) {
            try {
                SSLParameters.class.getMethod("setApplicationProtocols", String[].class).invoke(params, new Object[] {new String[] {alpn}});
            } catch (Throwable ignored) {
                // ALPN is optional. DoT still works without it.
            }
        }
        ssl.setSSLParameters(params);
        ssl.setSoTimeout(remaining(deadline));
        try {
            ssl.startHandshake();
        } catch (Exception error) {
            throw error;
        }
        return ssl;
    }

    private static Models.CertInfo readCert(SSLSocket ssl, String sni, boolean strict) {
        try {
            Certificate[] chain = ssl.getSession().getPeerCertificates();
            if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) return null;
            X509Certificate cert = (X509Certificate) chain[0];
            X509Certificate[] x509 = new X509Certificate[chain.length];
            for (int i = 0; i < chain.length; i++) {
                if (!(chain[i] instanceof X509Certificate)) return null;
                x509[i] = (X509Certificate) chain[i];
            }
            boolean authorized = true;
            String error = null;
            if (!strict) {
                String problem = trustProblem(x509, cert, sni);
                authorized = problem == null;
                error = problem;
            }
            byte[] sha = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            StringBuilder fp = new StringBuilder();
            for (int i = 0; i < sha.length; i++) {
                if (i > 0) fp.append(':');
                int v = sha[i] & 0xff;
                if (v < 16) fp.append('0');
                fp.append(Integer.toHexString(v).toUpperCase());
            }
            List<String> names = new ArrayList<String>();
            try {
                Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                if (sans != null) {
                    for (List<?> san : sans) {
                        int type = ((Integer) san.get(0)).intValue();
                        if ((type == 2 || type == 7) && san.get(1) != null) names.add(String.valueOf(san.get(1)));
                        if (names.size() >= 8) break;
                    }
                }
            } catch (Exception ignored) {
                // Some certificates omit parsable SANs. The subject is still shown.
            }
            String subjectDn = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
            String issuerDn = cert.getIssuerX500Principal().getName(X500Principal.RFC2253);
            String subject = rdn(subjectDn, "CN");
            if (subject.length() == 0) subject = rdn(subjectDn, "O");
            if (subject.length() == 0 && names.size() > 0) subject = names.get(0);
            String issuer = rdn(issuerDn, "O");
            if (issuer.length() == 0) issuer = rdn(issuerDn, "CN");
            Date notAfter = cert.getNotAfter();
            int days = notAfter == null ? 0 : (int) ((notAfter.getTime() - System.currentTimeMillis()) / 86400000L);
            String from = cert.getNotBefore() == null ? "" : cert.getNotBefore().toString();
            String to = notAfter == null ? "" : notAfter.toString();
            return new Models.CertInfo(subject, issuer, from, to, days, fp.toString(), names, authorized, error);
        } catch (Exception error) {
            return new Models.CertInfo("", "", "", "", 0, "", new ArrayList<String>(), false, Present.explain(error).message);
        }
    }

    /** Independent of the handshake, so a relaxed check can still say the certificate is not trusted. */
    private static String trustProblem(X509Certificate[] chain, X509Certificate leaf, String identity) {
        try {
            leaf.checkValidity();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            X509TrustManager tm = null;
            TrustManager[] managers = tmf.getTrustManagers();
            for (int i = 0; i < managers.length; i++) {
                if (managers[i] instanceof X509TrustManager) tm = (X509TrustManager) managers[i];
            }
            if (tm == null) return "The certificate chain is not trusted.";
            String algorithm = leaf.getPublicKey().getAlgorithm();
            String[] auths = new String[] {algorithm, "UNKNOWN", "RSA", "ECDSA", "EC"};
            Exception last = null;
            boolean trusted = false;
            for (int i = 0; i < auths.length; i++) {
                if (auths[i] == null || auths[i].length() == 0) continue;
                try {
                    tm.checkServerTrusted(chain, auths[i]);
                    trusted = true;
                    break;
                } catch (Exception error) {
                    last = error;
                }
            }
            if (!trusted) return Present.explain(last == null ? new java.security.cert.CertificateException("untrusted") : last).message;
            if (identity != null && identity.length() > 0 && !hostnameMatches(identity, leaf)) {
                return "The certificate is not valid for this hostname.";
            }
            return null;
        } catch (Exception error) {
            return Present.explain(error).message;
        }
    }

    private static boolean hostnameMatches(String host, X509Certificate cert) {
        String name = host.toLowerCase();
        try {
            java.util.Collection<java.util.List<?>> sans = cert.getSubjectAlternativeNames();
            boolean sawName = false;
            if (sans != null) {
                for (java.util.List<?> san : sans) {
                    int type = ((Integer) san.get(0)).intValue();
                    String value = sanValue(san.get(1));
                    if (value == null) continue;
                    if (type == 2) {
                        sawName = true;
                        if (dnsMatch(name, value.toLowerCase())) return true;
                    } else if (type == 7) {
                        sawName = true;
                        if (name.equals(value.toLowerCase())) return true;
                    }
                }
            }
            if (sawName) return false;
        } catch (Exception ignored) {
            // Fall through to the subject CN.
        }
        String cn = rdn(cert.getSubjectX500Principal().getName(X500Principal.RFC2253), "CN").toLowerCase();
        return cn.length() > 0 && dnsMatch(name, cn);
    }

    private static String sanValue(Object value) {
        if (value == null) return null;
        if (value instanceof byte[]) {
            try {
                return java.net.InetAddress.getByAddress((byte[]) value).getHostAddress();
            } catch (Exception error) {
                return null;
            }
        }
        return String.valueOf(value);
    }

    private static boolean dnsMatch(String host, String pattern) {
        if (pattern.startsWith("*.")) {
            String rest = pattern.substring(2);
            int dot = host.indexOf('.');
            if (dot <= 0) return false;
            return host.substring(dot + 1).equals(rest) && host.indexOf('.') == dot;
        }
        return host.equals(pattern);
    }

    private static Models.Transport transportOf(SSLSocket ssl, String address, int port) {
        Models.Transport transport = Models.Transport.empty();
        transport.remoteAddress = ssl.getInetAddress() != null ? ssl.getInetAddress().getHostAddress() : address;
        transport.remotePort = Integer.valueOf(ssl.getPort() > 0 ? ssl.getPort() : port);
        try {
            transport.tls = ssl.getSession().getProtocol();
            transport.cipher = ssl.getSession().getCipherSuite();
        } catch (Exception ignored) {
            // Timing still stands if the session hides the suite.
        }
        try {
            Object alpn = ssl.getClass().getMethod("getApplicationProtocol").invoke(ssl);
            if (alpn instanceof String && ((String) alpn).length() > 0) transport.alpn = (String) alpn;
        } catch (Throwable ignored) {
            // Older devices don't expose ALPN. The exchange line doesn't depend on it.
        }
        return transport;
    }

    private static final class Http {
        final int status;
        final String contentType;
        final byte[] body;

        Http(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }
    }

    private static Http parseHttp(byte[] raw) {
        int split = indexOf(raw, "\r\n\r\n");
        if (split < 0) throw new ProbeException("The resolver returned an incomplete HTTP response.", "malformed");
        String header = ascii(raw, 0, split);
        byte[] rest = new byte[raw.length - (split + 4)];
        System.arraycopy(raw, split + 4, rest, 0, rest.length);
        String[] lines = header.split("\r\n");
        int status = 0;
        if (lines.length > 0) {
            String[] parts = lines[0].split(" ");
            if (parts.length > 1) {
                try {
                    status = Integer.parseInt(parts[1]);
                } catch (NumberFormatException ignored) {
                    status = 0;
                }
            }
        }
        String contentType = null;
        int contentLength = -1;
        boolean chunked = false;
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon <= 0) continue;
            String key = lines[i].substring(0, colon).trim().toLowerCase();
            String value = lines[i].substring(colon + 1).trim();
            if ("content-type".equals(key)) contentType = value;
            if ("content-length".equals(key)) {
                try {
                    contentLength = Integer.parseInt(value);
                } catch (NumberFormatException ignored) {
                    contentLength = -1;
                }
            }
            if ("transfer-encoding".equals(key) && value.toLowerCase().indexOf("chunked") >= 0) chunked = true;
        }
        byte[] body = rest;
        if (chunked) body = decodeChunks(rest);
        else if (contentLength >= 0 && contentLength < body.length) {
            byte[] exact = new byte[contentLength];
            System.arraycopy(body, 0, exact, 0, contentLength);
            body = exact;
        }
        if (body.length > 65535) throw new ProbeException("The DNS response was too large.", "malformed");
        return new Http(status, contentType, body);
    }

    private static byte[] decodeChunks(byte[] rest) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int i = 0;
            while (i < rest.length) {
                int line = indexFrom(rest, i, "\r\n");
                if (line < 0) break;
                String sizeText = ascii(rest, i, line - i).trim();
                int semi = sizeText.indexOf(';');
                if (semi >= 0) sizeText = sizeText.substring(0, semi).trim();
                int size = Integer.parseInt(sizeText, 16);
                i = line + 2;
                if (size == 0) break;
                if (i + size > rest.length) break;
                out.write(rest, i, size);
                i += size + 2;
            }
            return out.toByteArray();
        } catch (Exception error) {
            return rest;
        }
    }

    private static byte[] readUntilClose(InputStream in, long deadline) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        while (out.size() < 200000) {
            if (System.currentTimeMillis() > deadline) throw new SocketTimeoutException("Timed out");
            int n = in.read(buf);
            if (n < 0) break;
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static byte[] readExact(InputStream in, int n, long deadline) throws Exception {
        byte[] out = new byte[n];
        int off = 0;
        while (off < n) {
            if (System.currentTimeMillis() > deadline) throw new SocketTimeoutException("Timed out");
            int r = in.read(out, off, n - off);
            if (r < 0) throw new ProbeException("The connection closed before the DNS answer.", "ECONNRESET");
            off += r;
        }
        return out;
    }

    private static byte[] gunzip(byte[] body) {
        try {
            GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(body));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) >= 0) out.write(buf, 0, n);
            in.close();
            return out.toByteArray();
        } catch (Exception error) {
            return body;
        }
    }

    private static int remaining(long deadline) {
        long left = deadline - System.currentTimeMillis();
        if (left < 1) throw new ProbeException("Timed out before a DNS answer.", "timeout");
        return (int) Math.min(left, 12000);
    }

    private static int clamp(int value, int min, int max) {
        if (value < min) return 8000;
        return Math.min(max, value);
    }

    private static void close(Socket socket) {
        if (socket == null) return;
        try {
            socket.close();
        } catch (Exception ignored) {
            // Already finished.
        }
    }

    private static String rdn(String dn, String key) {
        String[] parts = dn.split(",");
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.startsWith(key + "=")) return part.substring(key.length() + 1).replace("\\,", ",");
        }
        return "";
    }

    private static String join(String sep, String... parts) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (parts[i] == null || parts[i].length() == 0) continue;
            if (out.length() > 0) out.append(sep);
            out.append(parts[i]);
        }
        return out.toString();
    }

    private static int indexOf(byte[] raw, String needle) {
        return indexFrom(raw, 0, needle);
    }

    private static int indexFrom(byte[] raw, int from, String needle) {
        byte[] n = needle.getBytes();
        outer:
        for (int i = from; i + n.length <= raw.length; i++) {
            for (int j = 0; j < n.length; j++) {
                if (raw[i + j] != n[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static String ascii(byte[] buf, int offset, int len) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < len; i++) s.append((char) (buf[offset + i] & 0xff));
        return s.toString();
    }
}
