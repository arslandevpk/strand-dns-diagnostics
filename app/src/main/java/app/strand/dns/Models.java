package app.strand.dns;

import java.util.ArrayList;
import java.util.List;

/** Plain result types shared by the on-device probe and the screens. */
public final class Models {
    private Models() {}

    public static final class CheckInput {
        public final String protocol;
        public final String endpoint;
        public final String name;
        public final String qtype;
        public final boolean strict;
        public final int timeoutMs;

        public CheckInput(String protocol, String endpoint, String name, String qtype, boolean strict, int timeoutMs) {
            this.protocol = protocol;
            this.endpoint = endpoint;
            this.name = name;
            this.qtype = qtype;
            this.strict = strict;
            this.timeoutMs = timeoutMs;
        }

        public CheckInput withProtocol(String nextProtocol, String nextEndpoint) {
            return new CheckInput(nextProtocol, nextEndpoint, name, qtype, strict, timeoutMs);
        }
    }

    public static final class Stage {
        public final String id;
        public final String label;
        public final String state;
        public final String detail;
        public final Long ms;

        public Stage(String id, String label, String state, String detail, Long ms) {
            this.id = id;
            this.label = label;
            this.state = state;
            this.detail = detail;
            this.ms = ms;
        }
    }

    public static final class Answer {
        public final String name;
        public final String type;
        public final long ttl;
        public final String data;

        public Answer(String name, String type, long ttl, String data) {
            this.name = name;
            this.type = type;
            this.ttl = ttl;
            this.data = data;
        }
    }

    public static final class DnsView {
        public final int id;
        public final String rcode;
        public final boolean aa;
        public final boolean tc;
        public final boolean rd;
        public final boolean ra;
        public final boolean ad;
        public final boolean cd;
        public final int answerCount;
        public final int authorityCount;
        public final int additionalCount;
        public final List<Answer> answers;
        public final int wireBytes;
        public final boolean questionMatched;

        public DnsView(
                int id,
                String rcode,
                boolean aa,
                boolean tc,
                boolean rd,
                boolean ra,
                boolean ad,
                boolean cd,
                int answerCount,
                int authorityCount,
                int additionalCount,
                List<Answer> answers,
                int wireBytes,
                boolean questionMatched) {
            this.id = id;
            this.rcode = rcode;
            this.aa = aa;
            this.tc = tc;
            this.rd = rd;
            this.ra = ra;
            this.ad = ad;
            this.cd = cd;
            this.answerCount = answerCount;
            this.authorityCount = authorityCount;
            this.additionalCount = additionalCount;
            this.answers = answers;
            this.wireBytes = wireBytes;
            this.questionMatched = questionMatched;
        }
    }

    public static final class CertInfo {
        public final String subject;
        public final String issuer;
        public final String validFrom;
        public final String validTo;
        public final int daysRemaining;
        public final String fingerprint256;
        public final List<String> names;
        public final boolean authorized;
        public final String error;

        public CertInfo(
                String subject,
                String issuer,
                String validFrom,
                String validTo,
                int daysRemaining,
                String fingerprint256,
                List<String> names,
                boolean authorized,
                String error) {
            this.subject = subject;
            this.issuer = issuer;
            this.validFrom = validFrom;
            this.validTo = validTo;
            this.daysRemaining = daysRemaining;
            this.fingerprint256 = fingerprint256;
            this.names = names;
            this.authorized = authorized;
            this.error = error;
        }
    }

    public static final class Transport {
        public String remoteAddress;
        public Integer remotePort;
        public String alpn;
        public String tls;
        public String cipher;
        public Integer httpStatus;
        public String httpVersion;
        public String contentType;

        public static Transport empty() {
            return new Transport();
        }
    }

    public static final class Timing {
        public final long totalMs;
        public final Long dnsMs;
        public final Long tcpMs;
        public final Long tlsMs;
        public final Long queryMs;

        public Timing(long totalMs, Long dnsMs, Long tcpMs, Long tlsMs, Long queryMs) {
            this.totalMs = totalMs;
            this.dnsMs = dnsMs;
            this.tcpMs = tcpMs;
            this.tlsMs = tlsMs;
            this.queryMs = queryMs;
        }
    }

    public static final class ProbeResult {
        public String source;
        public String protocol;
        public String endpoint;
        public String host;
        public String queryName;
        public String qtype;
        public String verdict;
        public String summary;
        public String note;
        public String code;
        public Timing timing;
        public Transport transport;
        public CertInfo certificate;
        public DnsView dns;
        public List<Stage> stages;
        public String checkedAt;
    }

    public static final class Session {
        public String protocol = "doh";
        public String endpoint = "";
        public String name = "example.com";
        public String qtype = "A";
        public boolean strict = true;
        public String screen = "home";
        public ProbeResult primary;
        public ProbeResult pairDoh;
        public ProbeResult pairDot;
        public final List<ProbeResult> history = new ArrayList<ProbeResult>();

        public void setProtocol(String next) {
            String want = "dot".equals(next) ? "dot" : "doh";
            String current = endpoint == null ? "" : endpoint.trim();
            Endpoints.Preset preset = null;
            for (int i = 0; i < Endpoints.PRESETS.length; i++) {
                Endpoints.Preset item = Endpoints.PRESETS[i];
                if (item.doh.equals(current) || item.dot.equals(current)) {
                    preset = item;
                    break;
                }
            }
            if (preset != null) {
                protocol = want;
                endpoint = "doh".equals(want) ? preset.doh : preset.dot;
                return;
            }
            if (current.length() == 0) {
                protocol = want;
                return;
            }
            Endpoints.Both both = Endpoints.bothEndpoints(current, protocol);
            if (both.error == null) {
                protocol = want;
                endpoint = "doh".equals(want) ? both.doh : both.dot;
                return;
            }
            protocol = want;
        }

        public void applyPreset(Endpoints.Preset preset) {
            endpoint = "dot".equals(protocol) ? preset.dot : preset.doh;
        }

        public void remember(ProbeResult result, ProbeResult doh, ProbeResult dot) {
            primary = result;
            pairDoh = doh;
            pairDot = dot;
            String id = idOf(result);
            for (int i = history.size() - 1; i >= 0; i--) {
                if (id.equals(idOf(history.get(i)))) history.remove(i);
            }
            history.add(0, result);
            while (history.size() > 8) history.remove(history.size() - 1);
        }

        public void openResult(ProbeResult result) {
            primary = result;
            protocol = result.protocol;
            endpoint = result.endpoint;
            name = result.queryName;
            qtype = result.qtype;
            pairDoh = null;
            pairDot = null;
            screen = "diagnostics";
        }

        public static String idOf(ProbeResult result) {
            return result.checkedAt + "|" + result.protocol + "|" + result.host + "|" + result.queryName + "|" + result.qtype;
        }
    }
}
