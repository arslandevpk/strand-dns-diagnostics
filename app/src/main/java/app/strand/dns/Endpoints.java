package app.strand.dns;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Resolver presets and DoH / DoT address parsing. Same rules as Strand. */
public final class Endpoints {
    private Endpoints() {}

    public static final class Preset {
        public final String id;
        public final String name;
        public final String hint;
        public final String doh;
        public final String dot;

        public Preset(String id, String name, String hint, String doh, String dot) {
            this.id = id;
            this.name = name;
            this.hint = hint;
            this.doh = doh;
            this.dot = dot;
        }
    }

    public static final Preset[] PRESETS = {
        new Preset("cloudflare", "Cloudflare", "1.1.1.1", "https://cloudflare-dns.com/dns-query", "one.one.one.one"),
        new Preset("cloudflare-security", "Cloudflare Security", "malware", "https://security.cloudflare-dns.com/dns-query", "security.cloudflare-dns.com"),
        new Preset("cloudflare-family", "Cloudflare Family", "malware + adult", "https://family.cloudflare-dns.com/dns-query", "family.cloudflare-dns.com"),
        new Preset("google", "Google", "8.8.8.8", "https://dns.google/dns-query", "dns.google"),
        new Preset("quad9", "Quad9", "9.9.9.9", "https://dns.quad9.net/dns-query", "dns.quad9.net"),
        new Preset("adguard", "AdGuard", "ads", "https://dns.adguard-dns.com/dns-query", "dns.adguard-dns.com"),
        new Preset("adguard-family", "AdGuard Family", "ads + adult", "https://dns-family.adguard-dns.com/dns-query", "dns-family.adguard-dns.com"),
        new Preset("mullvad", "Mullvad", "unfiltered", "https://dns.mullvad.net/dns-query", "dns.mullvad.net"),
        new Preset("mullvad-adblock", "Mullvad Adblock", "ads", "https://adblock.dns.mullvad.net/dns-query", "adblock.dns.mullvad.net"),
        new Preset("opendns", "OpenDNS", "208.67.222.222", "https://doh.opendns.com/dns-query", "dns.opendns.com"),
        new Preset("cleanbrowsing", "CleanBrowsing", "security", "https://doh.cleanbrowsing.org/doh/security-filter/", "security-filter-dns.cleanbrowsing.org"),
        new Preset("controld", "Control D", "free", "https://freedns.controld.com/p0", "p0.freedns.controld.com"),
    };

    public static final class Parsed {
        public final boolean ok;
        public final String error;
        public final String protocol;
        public final String endpoint;
        public final String host;
        public final String path;
        public final String connectHost;
        public final String servername;
        public final int port;

        private Parsed(boolean ok, String error, String protocol, String endpoint, String host, String path, String connectHost, String servername, int port) {
            this.ok = ok;
            this.error = error;
            this.protocol = protocol;
            this.endpoint = endpoint;
            this.host = host;
            this.path = path;
            this.connectHost = connectHost;
            this.servername = servername;
            this.port = port;
        }

        static Parsed bad(String error) {
            return new Parsed(false, error, null, null, null, null, null, null, 0);
        }

        static Parsed doh(String endpoint, String host, String path) {
            return new Parsed(true, null, "doh", endpoint, host, path, null, null, 443);
        }

        static Parsed dot(String endpoint, String connectHost, String servername, int port) {
            return new Parsed(true, null, "dot", endpoint, null, null, connectHost, servername, port);
        }
    }

    public static final class Both {
        public final String doh;
        public final String dot;
        public final String error;

        private Both(String doh, String dot, String error) {
            this.doh = doh;
            this.dot = dot;
            this.error = error;
        }

        static Both ok(String doh, String dot) {
            return new Both(doh, dot, null);
        }

        static Both bad(String error) {
            return new Both(null, null, error);
        }
    }

    public static String normalizeQueryName(String input) {
        String raw = input == null ? "" : input.trim().replaceAll("\\.$", "");
        if (raw.length() == 0) throw new IllegalArgumentException("Enter a name to resolve.");
        if (raw.matches("(?i)^https?://.*") || raw.indexOf('/') >= 0 || raw.indexOf(' ') >= 0) {
            throw new IllegalArgumentException("That looks like a resolver address. Paste it in the resolver field.");
        }
        String host = raw.toLowerCase();
        if (hasNonAscii(host)) {
            try {
                String[] labels = host.split("\\.", -1);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < labels.length; i++) {
                    if (i > 0) sb.append('.');
                    sb.append(IDN.toASCII(labels[i]));
                }
                host = sb.toString().toLowerCase();
            } catch (RuntimeException error) {
                throw new IllegalArgumentException("That name isn't valid DNS.");
            }
        }
        if (host.length() > 253) throw new IllegalArgumentException("That name is too long.");
        String[] labels = host.split("\\.", -1);
        for (int i = 0; i < labels.length; i++) {
            String label = labels[i];
            if (label.length() == 0 || label.length() > 63 || !label.matches("(?i)^[a-z0-9_-]+$")) {
                throw new IllegalArgumentException("That name isn't valid DNS.");
            }
        }
        return host;
    }

    public static Parsed parseEndpoint(String raw, String protocol) {
        String text = raw == null ? "" : raw.trim();
        if (text.length() == 0) return Parsed.bad("Enter a resolver, or pick one.");
        if (text.length() > 300) return Parsed.bad("That endpoint is too long.");
        return "dot".equals(protocol) ? parseDot(text) : parseDoh(text);
    }

    public static List<Preset> filterPresets(String query) {
        String q = query == null ? "" : query.trim().toLowerCase();
        List<Preset> out = new ArrayList<Preset>();
        if (q.length() == 0 || q.indexOf("://") >= 0) {
            for (int i = 0; i < PRESETS.length && out.size() < 6; i++) {
                Preset preset = PRESETS[i];
                if (q.length() == 0
                        || preset.name.toLowerCase().indexOf(q) >= 0
                        || preset.doh.indexOf(q) >= 0
                        || preset.dot.indexOf(q) >= 0
                        || preset.hint.indexOf(q) >= 0) {
                    out.add(preset);
                }
            }
            return out;
        }
        for (int i = 0; i < PRESETS.length && out.size() < 6; i++) {
            Preset preset = PRESETS[i];
            String hay = (preset.name + " " + preset.hint + " " + preset.doh + " " + preset.dot).toLowerCase();
            if (hay.indexOf(q) >= 0) out.add(preset);
        }
        return out;
    }

    public static Preset matchPreset(String endpoint) {
        String trimmed = endpoint == null ? "" : endpoint.trim();
        String key = stripSlash(trimmed);
        for (int i = 0; i < PRESETS.length; i++) {
            Preset preset = PRESETS[i];
            if (stripSlash(preset.doh).equals(key) || preset.dot.equals(trimmed)) return preset;
        }
        return null;
    }

    public static Both bothEndpoints(String raw, String protocol) {
        Preset preset = matchPreset(raw);
        if (preset != null) return Both.ok(preset.doh, preset.dot);
        Parsed current = parseEndpoint(raw, protocol);
        if (!current.ok) return Both.bad(current.error);
        if ("doh".equals(current.protocol)) return Both.ok(current.endpoint, current.host);
        String name = current.servername != null && !isIp(current.servername) ? current.servername : current.connectHost;
        if (isIp(name)) return Both.bad("Add a hostname for DoH, or pick a resolver that publishes both.");
        return Both.ok("https://" + name + "/dns-query", current.endpoint);
    }

    public static boolean isQType(String value) {
        return "A".equals(value) || "AAAA".equals(value) || "TXT".equals(value) || "NS".equals(value) || "MX".equals(value) || "HTTPS".equals(value) || "CNAME".equals(value);
    }

    public static boolean isBlockedName(String host) {
        String h = host == null ? "" : host.toLowerCase().replaceAll("\\.$", "");
        if (h.length() == 0) return true;
        if ("localhost".equals(h) || h.endsWith(".localhost")) return true;
        if (h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".home.arpa")) return true;
        if ("metadata.google.internal".equals(h) || h.endsWith(".metadata.google.internal")) return true;
        return false;
    }

    public static boolean isIp(String host) {
        return isIpv4(host) || isIpv6(host);
    }

    private static Parsed parseDoh(String text) {
        String candidate = text;
        if (!candidate.matches("(?i)^https?://.*")) candidate = "https://" + candidate.replaceFirst("^/+", "");
        if (candidate.regionMatches(true, 0, "http://", 0, 7)) {
            return Parsed.bad("DNS over HTTPS has to be an https:// address.");
        }
        URI uri;
        try {
            uri = new URI(candidate);
        } catch (Exception error) {
            return Parsed.bad("That DoH address isn't a valid URL.");
        }
        if (uri.getUserInfo() != null) return Parsed.bad("Remove the username from the URL.");
        int port = uri.getPort();
        if (port != -1 && port != 443) return Parsed.bad("DoH checks use port 443.");
        String host = uri.getHost();
        if (host == null) return Parsed.bad("That DoH address isn't a valid URL.");
        host = host.replaceAll("^\\[|\\]$", "");
        if (hasNonAscii(host)) {
            try {
                host = IDN.toASCII(host);
            } catch (RuntimeException error) {
                return Parsed.bad("That DoH address isn't a valid URL.");
            }
        }
        host = host.toLowerCase();
        if (host.length() == 0 || isBlockedName(host)) return Parsed.bad("That hostname can't be checked.");
        String path = uri.getRawPath();
        if (path == null || path.length() == 0 || "/".equals(path)) path = "/dns-query";
        if (uri.getRawQuery() != null && uri.getRawQuery().length() > 0) path = path + "?" + uri.getRawQuery();
        String shown = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
        return Parsed.doh("https://" + shown + path, host, path);
    }

    private static Parsed parseDot(String text) {
        String body = text.replaceAll("(?i)^(tls|dot)://", "").replaceAll("/.*$", "");
        String connectHost = body;
        String servername = null;
        if (body.indexOf('#') >= 0) {
            int hash = body.indexOf('#');
            String left = body.substring(0, hash);
            String right = body.substring(hash + 1);
            if (left.length() == 0 || right.length() == 0) return Parsed.bad("Use host or ip#hostname.");
            if (isIp(left)) {
                connectHost = left;
                servername = right;
            } else if (isIp(right)) {
                connectHost = right;
                servername = left;
            } else {
                connectHost = left;
                servername = right;
            }
        }
        int port = 853;
        if (connectHost.startsWith("[")) {
            Matcher match = Pattern.compile("^\\[([^\\]]+)\\](?::(\\d+))?$").matcher(connectHost);
            if (!match.matches()) return Parsed.bad("That DoT address isn't valid.");
            connectHost = match.group(1);
            if (match.group(2) != null) port = Integer.parseInt(match.group(2));
        } else if (!isIpv6(connectHost)) {
            int idx = connectHost.lastIndexOf(':');
            if (idx > 0 && connectHost.substring(idx + 1).matches("\\d+")) {
                port = Integer.parseInt(connectHost.substring(idx + 1));
                connectHost = connectHost.substring(0, idx);
            }
        }
        if (port != 853) return Parsed.bad("DoT checks use port 853.");
        connectHost = connectHost.trim().toLowerCase();
        if (servername != null) servername = servername.trim().toLowerCase();
        if (connectHost.length() == 0 || (!isIp(connectHost) && isBlockedName(connectHost))) {
            return Parsed.bad("That hostname can't be checked.");
        }
        if (servername != null && !isIp(servername) && isBlockedName(servername)) {
            return Parsed.bad("That hostname can't be checked.");
        }
        String endpoint = servername != null && !servername.equals(connectHost) ? connectHost + "#" + servername : connectHost;
        return Parsed.dot(endpoint, connectHost, servername, port);
    }

    private static boolean isIpv4(String host) {
        return ipv4Parts(host) != null;
    }

    private static boolean isIpv6(String host) {
        return expandIpv6(host) != null;
    }

    private static int[] ipv4Parts(String host) {
        Matcher match = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$").matcher(host);
        if (!match.matches()) return null;
        int[] parts = new int[4];
        for (int i = 0; i < 4; i++) {
            String part = match.group(i + 1);
            if (part.length() > 1 && part.charAt(0) == '0') return null;
            int n = Integer.parseInt(part);
            if (n < 0 || n > 255) return null;
            parts[i] = n;
        }
        return parts;
    }

    private static int[] expandIpv6(String ip) {
        if (ip == null || ip.indexOf(':') < 0) return null;
        String value = ip.toLowerCase().split("%", 2)[0];
        int dot = value.lastIndexOf('.');
        if (dot >= 0) {
            int last = value.lastIndexOf(':');
            int[] v4 = ipv4Parts(value.substring(last + 1));
            if (v4 == null) return null;
            String hi = Integer.toHexString((v4[0] << 8) | v4[1]);
            String lo = Integer.toHexString((v4[2] << 8) | v4[3]);
            value = value.substring(0, last + 1) + hi + ":" + lo;
        }
        String[] halves = value.split("::", -1);
        if (halves.length > 2) return null;
        String[] left = halves[0].length() == 0 ? new String[0] : halves[0].split(":", -1);
        String[] right = halves.length == 2 && halves[1].length() > 0 ? halves[1].split(":", -1) : new String[0];
        if (halves.length == 1 && left.length != 8) return null;
        int missing = 8 - (left.length + right.length);
        if (missing < 0) return null;
        String[] parts = new String[8];
        int p = 0;
        for (int i = 0; i < left.length; i++) parts[p++] = left[i];
        int fill = halves.length == 2 ? missing : 0;
        for (int i = 0; i < fill; i++) parts[p++] = "0";
        for (int i = 0; i < right.length; i++) parts[p++] = right[i];
        if (p != 8) return null;
        int[] nums = new int[8];
        for (int i = 0; i < 8; i++) {
            if (!parts[i].matches("^[0-9a-f]{1,4}$")) return null;
            nums[i] = Integer.parseInt(parts[i], 16);
        }
        return nums;
    }

    private static boolean hasNonAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 127) return true;
        }
        return false;
    }

    private static String stripSlash(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '/') end--;
        return value.substring(0, end);
    }
}
