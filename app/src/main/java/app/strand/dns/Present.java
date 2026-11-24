package app.strand.dns;

import java.util.ArrayList;
import java.util.List;

/** Verdicts and the sentences the report shows. */
public final class Present {
    private Present() {}

    public static final class Explained {
        public final String message;
        public final String code;

        public Explained(String message, String code) {
            this.message = message;
            this.code = code;
        }
    }

    public static String decideVerdict(Models.DnsView dns, Boolean certAuthorized, boolean strict) {
        if (dns == null || !dns.questionMatched) return "down";
        if (dns.tc && dns.answers.size() == 0) return "degraded";
        if (strict && Boolean.FALSE.equals(certAuthorized)) return "degraded";
        if ("NOERROR".equals(dns.rcode) || "NXDOMAIN".equals(dns.rcode)) return "up";
        return "degraded";
    }

    public static String summarize(Models.DnsView dns, String name, String qtype, String fallback) {
        if (dns == null) return fallback != null ? fallback : "No DNS answer came back.";
        if (!dns.questionMatched) return "The reply didn't match the query that was sent.";
        if ("NXDOMAIN".equals(dns.rcode)) return name + " does not exist. The resolver itself answered.";
        if ("NOERROR".equals(dns.rcode) && dns.answers.size() == 0) {
            return name + " has no " + qtype + " data. The resolver answered.";
        }
        if ("NOERROR".equals(dns.rcode)) {
            Models.Answer first = dns.answers.get(0);
            String more = dns.answers.size() > 1 ? " and " + (dns.answers.size() - 1) + " more" : "";
            return first.type + " " + first.data + more;
        }
        if ("REFUSED".equals(dns.rcode)) return "The resolver refused the query.";
        if ("SERVFAIL".equals(dns.rcode)) return "The resolver failed while answering.";
        return "The resolver returned " + dns.rcode + ".";
    }

    public static String headlineOf(Models.ProbeResult result) {
        Models.DnsView dns = result.dns;
        if (dns != null && "NOERROR".equals(dns.rcode) && dns.answers.size() > 0) return dns.answers.get(0).data;
        if (dns != null && "NOERROR".equals(dns.rcode)) return "No data";
        if (dns != null && "NXDOMAIN".equals(dns.rcode)) return "No such name";
        if (dns != null) return dns.rcode;
        if ("timeout".equals(result.code)) return "Timed out";
        if ("private".equals(result.code)) return "Private address";
        return "No answer";
    }

    public static String verdictLabel(String verdict) {
        if ("up".equals(verdict)) return "Up";
        if ("degraded".equals(verdict)) return "Degraded";
        return "Down";
    }

    public static String stageLabel(String id) {
        if ("resolve".equals(id)) return "Resolve";
        if ("tcp".equals(id)) return "TCP";
        if ("tls".equals(id)) return "TLS";
        if ("exchange".equals(id)) return "Exchange";
        if ("dns".equals(id)) return "DNS";
        return id;
    }

    public static List<Models.Stage> stages(Models.Stage... known) {
        String[] order = {"resolve", "tcp", "tls", "exchange", "dns"};
        List<Models.Stage> out = new ArrayList<Models.Stage>();
        for (int i = 0; i < order.length; i++) {
            Models.Stage found = null;
            if (known != null) {
                for (int j = 0; j < known.length; j++) {
                    if (known[j] != null && order[i].equals(known[j].id)) found = known[j];
                }
            }
            if (found != null) out.add(found);
            else out.add(new Models.Stage(order[i], stageLabel(order[i]), "skip", "Not reached", null));
        }
        return out;
    }

    public static Models.Stage stage(String id, String state, String detail, Long ms) {
        return new Models.Stage(id, stageLabel(id), state, detail, ms);
    }

    public static Models.ProbeResult failure(
            String protocol,
            String qtype,
            String endpoint,
            String host,
            String queryName,
            String message,
            String code,
            long timingMs,
            List<Models.Stage> stages) {
        Models.ProbeResult result = new Models.ProbeResult();
        result.source = "device";
        result.protocol = protocol;
        result.endpoint = endpoint == null ? "" : endpoint;
        result.host = host == null ? "" : host;
        result.queryName = queryName == null ? "" : queryName;
        result.qtype = qtype;
        result.verdict = "down";
        result.summary = message;
        result.note = null;
        result.code = code;
        result.timing = new Models.Timing(timingMs, null, null, null, null);
        result.transport = Models.Transport.empty();
        result.certificate = null;
        result.dns = null;
        if (stages != null) result.stages = stages;
        else result.stages = stages(stage("resolve", "fail", message, timingMs > 0 ? Long.valueOf(timingMs) : null));
        result.checkedAt = Iso.now();
        return result;
    }

    public static Explained explain(Throwable err) {
        if (err instanceof Probe.ProbeException) {
            Probe.ProbeException probe = (Probe.ProbeException) err;
            return new Explained(probe.getMessage(), probe.code);
        }
        String type = err == null ? "" : err.getClass().getSimpleName();
        String message = err == null || err.getMessage() == null ? "The check failed." : err.getMessage().replaceAll("\\s+", " ");
        if (message.length() > 280) message = message.substring(0, 280);
        String lower = message.toLowerCase();
        if ("SocketTimeoutException".equals(type) || lower.indexOf("timed out") >= 0) {
            return new Explained("Timed out before a DNS answer.", "timeout");
        }
        if ("UnknownHostException".equals(type)) return new Explained("The hostname did not resolve.", "ENOTFOUND");
        if ("ConnectException".equals(type)) return new Explained("The endpoint refused the connection.", "ECONNREFUSED");
        if ("NoRouteToHostException".equals(type)) return new Explained("There is no route to that host.", "EHOSTUNREACH");
        if (type.indexOf("Expired") >= 0 || lower.indexOf("expired") >= 0 || lower.indexOf("notafter") >= 0) {
            return new Explained("The certificate has expired.", "cert");
        }
        boolean certType = type.indexOf("Certificate") >= 0 || type.indexOf("CertPath") >= 0 || type.indexOf("Validator") >= 0;
        boolean certMsg = lower.indexOf("certificate") >= 0 || lower.indexOf("trust anchor") >= 0 || lower.indexOf("certpath") >= 0;
        if (certType || ("SSLHandshakeException".equals(type) && certMsg)) {
            if (lower.indexOf("hostname") >= 0 || lower.indexOf("subject alternative") >= 0 || lower.indexOf("altname") >= 0) {
                return new Explained("The certificate is not valid for this hostname.", "cert");
            }
            if (lower.indexOf("self") >= 0 && lower.indexOf("sign") >= 0) {
                return new Explained("The certificate is self-signed and not trusted.", "cert");
            }
            return new Explained("The certificate chain is not trusted.", "cert");
        }
        if ("SSLHandshakeException".equals(type) || "SSLException".equals(type) || "SSLProtocolException".equals(type)) {
            return new Explained(message.length() == 0 ? "The TLS handshake failed." : message, "tls");
        }
        return new Explained(message, "error");
    }

    public static String dnsDetail(Models.DnsView dns) {
        StringBuilder flags = new StringBuilder();
        if (dns.aa) flags.append("AA ");
        if (dns.tc) flags.append("TC ");
        if (dns.rd) flags.append("RD ");
        if (dns.ra) flags.append("RA ");
        if (dns.ad) flags.append("AD ");
        if (dns.cd) flags.append("CD ");
        String flagText = flags.toString().trim();
        if (flagText.length() == 0) flagText = "no flags";
        String noun = dns.answerCount == 1 ? "answer" : "answers";
        return dns.rcode + " · " + dns.answerCount + " " + noun + " · " + flagText + " · id " + dns.id;
    }
}
