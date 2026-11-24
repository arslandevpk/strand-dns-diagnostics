package app.strand.dns;

public final class SelfTest {
    public static void main(String[] args) {
        byte[] query = DnsCodec.encodeQuery("example.com", "A", 0xABCD);
        expect(query.length == 12 + 1 + 7 + 1 + 3 + 1 + 4, "query length");
        expect((query[0] & 0xff) == 0xAB && (query[1] & 0xff) == 0xCD, "query id");
        expect(query[12] == 7, "label length");
        Models.DnsView decoded = DnsCodec.decodeMessage(responseExample(), 0xABCD, "example.com");
        expect(decoded.questionMatched, "question matched");
        expect("NOERROR".equals(decoded.rcode), "rcode");
        expect(decoded.answers.size() == 1 && "1.2.3.4".equals(decoded.answers.get(0).data), "answer");

        Endpoints.Parsed doh = Endpoints.parseEndpoint("cloudflare-dns.com", "doh");
        expect(doh.ok && "https://cloudflare-dns.com/dns-query".equals(doh.endpoint), "doh parse");
        Endpoints.Parsed dot = Endpoints.parseEndpoint("1.1.1.1#one.one.one.one", "dot");
        expect(dot.ok && "1.1.1.1".equals(dot.connectHost) && "one.one.one.one".equals(dot.servername), "dot parse");
        Endpoints.Both both = Endpoints.bothEndpoints("https://dns.google/dns-query", "doh");
        expect(both.error == null && "dns.google".equals(both.dot), "both from preset");
        try {
            Endpoints.normalizeQueryName("https://example.com");
            expect(false, "reject url name");
        } catch (IllegalArgumentException expected) {
            expect(true, "reject url name");
        }

        System.out.println("-- DoH cloudflare --");
        Models.ProbeResult dohResult = Probe.run(new Models.CheckInput("doh", "https://cloudflare-dns.com/dns-query", "example.com", "A", true, 8000));
        dump(dohResult);
        System.out.println("-- DoT one.one.one.one --");
        Models.ProbeResult dotResult = Probe.run(new Models.CheckInput("dot", "one.one.one.one", "example.com", "A", true, 8000));
        dump(dotResult);
        if (!"up".equals(dohResult.verdict)) {
            System.exit(1);
        }
    }

    private static byte[] responseExample() {
        byte[] q = DnsCodec.encodeQuery("example.com", "A", 0xABCD);
        byte[] msg = new byte[q.length + 16];
        System.arraycopy(q, 0, msg, 0, q.length);
        msg[2] = (byte) 0x81;
        msg[3] = (byte) 0x80;
        msg[6] = 0;
        msg[7] = 1;
        int name = q.length;
        msg[name] = (byte) 0xC0;
        msg[name + 1] = 12;
        msg[name + 2] = 0;
        msg[name + 3] = 1;
        msg[name + 4] = 0;
        msg[name + 5] = 1;
        msg[name + 6] = 0;
        msg[name + 7] = 0;
        msg[name + 8] = 0;
        msg[name + 9] = 60;
        msg[name + 10] = 0;
        msg[name + 11] = 4;
        msg[name + 12] = 1;
        msg[name + 13] = 2;
        msg[name + 14] = 3;
        msg[name + 15] = 4;
        return msg;
    }

    private static void dump(Models.ProbeResult result) {
        System.out.println(result.verdict + " " + result.summary + " (" + result.timing.totalMs + " ms)");
        if (result.note != null) System.out.println(result.note);
        if (result.certificate != null) {
            System.out.println("cert " + result.certificate.subject + " trusted=" + result.certificate.authorized + " " + result.certificate.daysRemaining + "d");
        }
        for (int i = 0; i < result.stages.size(); i++) {
            Models.Stage stage = result.stages.get(i);
            System.out.println("  " + stage.state + " " + stage.label + " " + stage.detail + (stage.ms == null ? "" : " " + stage.ms + "ms"));
        }
    }

    private static void expect(boolean ok, String label) {
        if (!ok) throw new AssertionError(label);
        System.out.println("ok " + label);
    }
}
