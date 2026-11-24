package app.strand.dns;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** Remembers the last check on the device. Nothing is uploaded. */
public final class Store {
    private static final String PREFS = "strand.v1";
    private final SharedPreferences prefs;

    public Store(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public Models.Session load() {
        Models.Session session = new Models.Session();
        String raw = prefs.getString("session", null);
        if (raw == null) return session;
        try {
            JSONObject json = new JSONObject(raw);
            session.protocol = "dot".equals(json.optString("protocol")) ? "dot" : "doh";
            session.endpoint = json.optString("endpoint", "");
            session.name = json.optString("name", "example.com");
            if (session.name.length() == 0) session.name = "example.com";
            session.qtype = Endpoints.isQType(json.optString("qtype")) ? json.optString("qtype") : "A";
            session.strict = json.optBoolean("strict", true);
            session.screen = "diagnostics".equals(json.optString("screen")) ? "diagnostics" : "home";
            session.primary = result(json.optJSONObject("primary"));
            session.pairDoh = result(json.optJSONObject("pairDoh"));
            session.pairDot = result(json.optJSONObject("pairDot"));
            JSONArray history = json.optJSONArray("history");
            if (history != null) {
                for (int i = 0; i < history.length() && session.history.size() < 8; i++) {
                    Models.ProbeResult item = result(history.optJSONObject(i));
                    if (item != null) session.history.add(item);
                }
            }
        } catch (Exception ignored) {
            return new Models.Session();
        }
        return session;
    }

    public void save(Models.Session session) {
        try {
            JSONObject json = new JSONObject();
            json.put("protocol", session.protocol);
            json.put("endpoint", session.endpoint);
            json.put("name", session.name);
            json.put("qtype", session.qtype);
            json.put("strict", session.strict);
            json.put("screen", session.screen);
            json.put("primary", nullable(resultJson(session.primary)));
            json.put("pairDoh", nullable(resultJson(session.pairDoh)));
            json.put("pairDot", nullable(resultJson(session.pairDot)));
            JSONArray history = new JSONArray();
            for (int i = 0; i < session.history.size(); i++) history.put(resultJson(session.history.get(i)));
            json.put("history", history);
            prefs.edit().putString("session", json.toString()).apply();
        } catch (Exception ignored) {
            // A full store shouldn't block the check the user just ran.
        }
    }

    private static JSONObject resultJson(Models.ProbeResult result) throws Exception {
        if (result == null) return null;
        JSONObject json = new JSONObject();
        json.put("source", "device");
        json.put("protocol", result.protocol);
        json.put("endpoint", result.endpoint);
        json.put("host", result.host);
        json.put("queryName", result.queryName);
        json.put("qtype", result.qtype);
        json.put("verdict", result.verdict);
        json.put("summary", result.summary);
        json.put("note", result.note == null ? JSONObject.NULL : result.note);
        json.put("code", result.code == null ? JSONObject.NULL : result.code);
        json.put("checkedAt", result.checkedAt);
        JSONObject timing = new JSONObject();
        timing.put("totalMs", result.timing.totalMs);
        timing.put("dnsMs", result.timing.dnsMs == null ? JSONObject.NULL : result.timing.dnsMs);
        timing.put("tcpMs", result.timing.tcpMs == null ? JSONObject.NULL : result.timing.tcpMs);
        timing.put("tlsMs", result.timing.tlsMs == null ? JSONObject.NULL : result.timing.tlsMs);
        timing.put("queryMs", result.timing.queryMs == null ? JSONObject.NULL : result.timing.queryMs);
        json.put("timing", timing);
        JSONObject transport = new JSONObject();
        transport.put("remoteAddress", result.transport.remoteAddress == null ? JSONObject.NULL : result.transport.remoteAddress);
        transport.put("remotePort", result.transport.remotePort == null ? JSONObject.NULL : result.transport.remotePort);
        transport.put("alpn", result.transport.alpn == null ? JSONObject.NULL : result.transport.alpn);
        transport.put("tls", result.transport.tls == null ? JSONObject.NULL : result.transport.tls);
        transport.put("cipher", result.transport.cipher == null ? JSONObject.NULL : result.transport.cipher);
        transport.put("httpStatus", result.transport.httpStatus == null ? JSONObject.NULL : result.transport.httpStatus);
        transport.put("httpVersion", result.transport.httpVersion == null ? JSONObject.NULL : result.transport.httpVersion);
        transport.put("contentType", result.transport.contentType == null ? JSONObject.NULL : result.transport.contentType);
        json.put("transport", transport);
        json.put("certificate", nullable(certJson(result.certificate)));
        json.put("dns", nullable(dnsJson(result.dns)));
        JSONArray stages = new JSONArray();
        for (int i = 0; i < result.stages.size(); i++) {
            Models.Stage stage = result.stages.get(i);
            JSONObject item = new JSONObject();
            item.put("id", stage.id);
            item.put("label", stage.label);
            item.put("state", stage.state);
            item.put("detail", stage.detail);
            item.put("ms", stage.ms == null ? JSONObject.NULL : stage.ms);
            stages.put(item);
        }
        json.put("stages", stages);
        return json;
    }

    private static JSONObject certJson(Models.CertInfo cert) throws Exception {
        if (cert == null) return null;
        JSONObject json = new JSONObject();
        json.put("subject", cert.subject);
        json.put("issuer", cert.issuer);
        json.put("validFrom", cert.validFrom);
        json.put("validTo", cert.validTo);
        json.put("daysRemaining", cert.daysRemaining);
        json.put("fingerprint256", cert.fingerprint256);
        json.put("authorized", cert.authorized);
        json.put("error", cert.error == null ? JSONObject.NULL : cert.error);
        JSONArray names = new JSONArray();
        for (int i = 0; i < cert.names.size(); i++) names.put(cert.names.get(i));
        json.put("names", names);
        return json;
    }

    private static JSONObject dnsJson(Models.DnsView dns) throws Exception {
        if (dns == null) return null;
        JSONObject json = new JSONObject();
        json.put("id", dns.id);
        json.put("rcode", dns.rcode);
        json.put("aa", dns.aa);
        json.put("tc", dns.tc);
        json.put("rd", dns.rd);
        json.put("ra", dns.ra);
        json.put("ad", dns.ad);
        json.put("cd", dns.cd);
        json.put("answerCount", dns.answerCount);
        json.put("authorityCount", dns.authorityCount);
        json.put("additionalCount", dns.additionalCount);
        json.put("wireBytes", dns.wireBytes);
        json.put("questionMatched", dns.questionMatched);
        JSONArray answers = new JSONArray();
        for (int i = 0; i < dns.answers.size(); i++) {
            Models.Answer answer = dns.answers.get(i);
            JSONObject item = new JSONObject();
            item.put("name", answer.name);
            item.put("type", answer.type);
            item.put("ttl", answer.ttl);
            item.put("data", answer.data);
            answers.put(item);
        }
        json.put("answers", answers);
        return json;
    }

    private static Object nullable(Object value) {
        return value == null ? JSONObject.NULL : value;
    }

    private static Models.ProbeResult result(JSONObject json) {
        if (json == null) return null;
        try {
            Models.ProbeResult result = new Models.ProbeResult();
            result.source = "device";
            result.protocol = "dot".equals(json.optString("protocol")) ? "dot" : "doh";
            result.endpoint = json.optString("endpoint", "");
            result.host = json.optString("host", "");
            result.queryName = json.optString("queryName", "");
            result.qtype = json.optString("qtype", "A");
            result.verdict = json.optString("verdict", "down");
            result.summary = json.optString("summary", "");
            result.note = json.isNull("note") ? null : json.optString("note", null);
            result.code = json.isNull("code") ? null : json.optString("code", null);
            result.checkedAt = json.optString("checkedAt", "");
            JSONObject timing = json.optJSONObject("timing");
            result.timing = new Models.Timing(
                    timing == null ? 0 : timing.optLong("totalMs"),
                    longOrNull(timing, "dnsMs"),
                    longOrNull(timing, "tcpMs"),
                    longOrNull(timing, "tlsMs"),
                    longOrNull(timing, "queryMs"));
            result.transport = transport(json.optJSONObject("transport"));
            result.certificate = cert(json.optJSONObject("certificate"));
            result.dns = dns(json.optJSONObject("dns"));
            result.stages = new ArrayList<Models.Stage>();
            JSONArray stages = json.optJSONArray("stages");
            if (stages != null) {
                for (int i = 0; i < stages.length(); i++) {
                    JSONObject item = stages.optJSONObject(i);
                    if (item == null) continue;
                    result.stages.add(new Models.Stage(
                            item.optString("id"),
                            item.optString("label"),
                            item.optString("state", "skip"),
                            item.optString("detail", ""),
                            item.isNull("ms") ? null : Long.valueOf(item.optLong("ms"))));
                }
            }
            return result;
        } catch (Exception error) {
            return null;
        }
    }

    private static Long longOrNull(JSONObject json, String key) {
        if (json == null || json.isNull(key)) return null;
        return Long.valueOf(json.optLong(key));
    }

    private static Models.Transport transport(JSONObject json) {
        Models.Transport transport = Models.Transport.empty();
        if (json == null) return transport;
        transport.remoteAddress = json.isNull("remoteAddress") ? null : json.optString("remoteAddress", null);
        transport.remotePort = json.isNull("remotePort") ? null : Integer.valueOf(json.optInt("remotePort"));
        transport.alpn = json.isNull("alpn") ? null : json.optString("alpn", null);
        transport.tls = json.isNull("tls") ? null : json.optString("tls", null);
        transport.cipher = json.isNull("cipher") ? null : json.optString("cipher", null);
        transport.httpStatus = json.isNull("httpStatus") ? null : Integer.valueOf(json.optInt("httpStatus"));
        transport.httpVersion = json.isNull("httpVersion") ? null : json.optString("httpVersion", null);
        transport.contentType = json.isNull("contentType") ? null : json.optString("contentType", null);
        return transport;
    }

    private static Models.CertInfo cert(JSONObject json) {
        if (json == null) return null;
        List<String> names = new ArrayList<String>();
        JSONArray array = json.optJSONArray("names");
        if (array != null) {
            for (int i = 0; i < array.length(); i++) names.add(array.optString(i));
        }
        return new Models.CertInfo(
                json.optString("subject", ""),
                json.optString("issuer", ""),
                json.optString("validFrom", ""),
                json.optString("validTo", ""),
                json.optInt("daysRemaining"),
                json.optString("fingerprint256", ""),
                names,
                json.optBoolean("authorized"),
                json.isNull("error") ? null : json.optString("error", null));
    }

    private static Models.DnsView dns(JSONObject json) {
        if (json == null) return null;
        List<Models.Answer> answers = new ArrayList<Models.Answer>();
        JSONArray array = json.optJSONArray("answers");
        if (array != null) {
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.optJSONObject(i);
                if (item == null) continue;
                answers.add(new Models.Answer(item.optString("name"), item.optString("type"), item.optLong("ttl"), item.optString("data")));
            }
        }
        return new Models.DnsView(
                json.optInt("id"),
                json.optString("rcode", ""),
                json.optBoolean("aa"),
                json.optBoolean("tc"),
                json.optBoolean("rd"),
                json.optBoolean("ra"),
                json.optBoolean("ad"),
                json.optBoolean("cd"),
                json.optInt("answerCount"),
                json.optInt("authorityCount"),
                json.optInt("additionalCount"),
                answers,
                json.optInt("wireBytes"),
                json.optBoolean("questionMatched"));
    }
}
