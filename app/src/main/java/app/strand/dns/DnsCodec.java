package app.strand.dns;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** DNS wire encode/decode for the query types Strand sends. */
public final class DnsCodec {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String[] RCODES = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};

    private DnsCodec() {}

    public static final class DnsParseError extends RuntimeException {
        public DnsParseError(String message) {
            super(message);
        }
    }

    public static int typeCode(String qtype) {
        if ("NS".equals(qtype)) return 2;
        if ("CNAME".equals(qtype)) return 5;
        if ("SOA".equals(qtype)) return 6;
        if ("MX".equals(qtype)) return 15;
        if ("TXT".equals(qtype)) return 16;
        if ("AAAA".equals(qtype)) return 28;
        if ("HTTPS".equals(qtype)) return 65;
        return 1;
    }

    public static String typeName(int code) {
        if (code == 1) return "A";
        if (code == 2) return "NS";
        if (code == 5) return "CNAME";
        if (code == 6) return "SOA";
        if (code == 15) return "MX";
        if (code == 16) return "TXT";
        if (code == 28) return "AAAA";
        if (code == 65) return "HTTPS";
        return "TYPE" + code;
    }

    public static byte[] encodeQuery(String name, String qtype) {
        return encodeQuery(name, qtype, RANDOM.nextInt(65536));
    }

    public static byte[] encodeQuery(String name, String qtype, int id) {
        byte[] qname = encodeName(name);
        byte[] bytes = new byte[12 + qname.length + 4];
        put16(bytes, 0, id);
        put16(bytes, 2, 0x0100);
        put16(bytes, 4, 1);
        System.arraycopy(qname, 0, bytes, 12, qname.length);
        int q = 12 + qname.length;
        put16(bytes, q, typeCode(qtype));
        put16(bytes, q + 2, 1);
        return bytes;
    }

    public static int readId(byte[] query) {
        return u16(query, 0);
    }

    public static Models.DnsView decodeMessage(byte[] buf, int expectId, String expectName) {
        if (buf.length < 12) throw new DnsParseError("DNS message is too short.");
        int id = u16(buf, 0);
        int flags = u16(buf, 2);
        int qd = u16(buf, 4);
        int an = u16(buf, 6);
        int ns = u16(buf, 8);
        int ar = u16(buf, 10);
        int offset = 12;
        String questionName = "";
        for (int i = 0; i < qd; i++) {
            Name name = readName(buf, offset, 0);
            offset = name.offset;
            if (offset + 4 > buf.length) throw new DnsParseError("DNS question is truncated.");
            offset += 4;
            if (i == 0) questionName = name.name;
        }
        List<Models.Answer> answers = new ArrayList<Models.Answer>();
        for (int i = 0; i < an; i++) {
            Rr rr = readRr(buf, offset);
            offset = rr.offset;
            answers.add(rr.answer);
        }
        for (int i = 0; i < ns + ar; i++) offset = skipRr(buf, offset);
        int rcodeN = flags & 0x0f;
        String expected = expectName.replaceAll("\\.$", "").toLowerCase();
        String got = questionName.replaceAll("\\.$", "").toLowerCase();
        boolean matched = qd > 0 && got.equals(expected) && id == expectId && bit(flags, 15);
        return new Models.DnsView(
                id,
                rcodeN < RCODES.length ? RCODES[rcodeN] : "RCODE" + rcodeN,
                bit(flags, 10),
                bit(flags, 9),
                bit(flags, 8),
                bit(flags, 7),
                bit(flags, 5),
                bit(flags, 4),
                an,
                ns,
                ar,
                answers,
                buf.length,
                matched);
    }

    private static byte[] encodeName(String name) {
        String[] labels = name.replaceAll("\\.$", "").split("\\.", -1);
        int size = 1;
        for (int i = 0; i < labels.length; i++) {
            if (labels[i].length() == 0 || labels[i].length() > 63) {
                throw new DnsParseError("That name isn't valid DNS.");
            }
            size += 1 + labels[i].length();
        }
        byte[] out = new byte[size];
        int pos = 0;
        for (int i = 0; i < labels.length; i++) {
            String label = labels[i];
            out[pos++] = (byte) label.length();
            for (int c = 0; c < label.length(); c++) out[pos++] = (byte) label.charAt(c);
        }
        out[pos] = 0;
        return out;
    }

    private static final class Name {
        final String name;
        final int offset;

        Name(String name, int offset) {
            this.name = name;
            this.offset = offset;
        }
    }

    private static Name readName(byte[] buf, int offset, int depth) {
        if (depth > 16) throw new DnsParseError("DNS name compression looped.");
        List<String> labels = new ArrayList<String>();
        int pos = offset;
        int end = offset;
        boolean jumped = false;
        while (pos < buf.length) {
            int len = buf[pos] & 0xff;
            if (len == 0) {
                if (!jumped) end = pos + 1;
                break;
            }
            if ((len & 0xc0) == 0xc0) {
                if (pos + 1 >= buf.length) throw new DnsParseError("DNS name pointer is truncated.");
                int ptr = ((len & 0x3f) << 8) | (buf[pos + 1] & 0xff);
                if (ptr >= buf.length) throw new DnsParseError("DNS name pointer is out of range.");
                if (!jumped) end = pos + 2;
                Name rest = readName(buf, ptr, depth + 1);
                if (rest.name.length() > 0) labels.add(rest.name);
                jumped = true;
                break;
            }
            if ((len & 0xc0) != 0) throw new DnsParseError("DNS name label is invalid.");
            pos += 1;
            if (pos + len > buf.length) throw new DnsParseError("DNS name label is truncated.");
            labels.add(ascii(buf, pos, len));
            pos += len;
            if (!jumped) end = pos;
        }
        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < labels.size(); i++) {
            if (i > 0) joined.append('.');
            joined.append(labels.get(i));
        }
        return new Name(joined.toString(), end);
    }

    private static final class Rr {
        final Models.Answer answer;
        final int offset;

        Rr(Models.Answer answer, int offset) {
            this.answer = answer;
            this.offset = offset;
        }
    }

    private static Rr readRr(byte[] buf, int offset) {
        Name name = readName(buf, offset, 0);
        int pos = name.offset;
        if (pos + 10 > buf.length) throw new DnsParseError("DNS record header is truncated.");
        int type = u16(buf, pos);
        long ttl = u32(buf, pos + 4);
        int rdlen = u16(buf, pos + 8);
        pos += 10;
        if (pos + rdlen > buf.length) throw new DnsParseError("DNS record data is truncated.");
        String data = rdata(buf, pos, rdlen, type);
        return new Rr(new Models.Answer(name.name, typeName(type), ttl, data), pos + rdlen);
    }

    private static int skipRr(byte[] buf, int offset) {
        Name name = readName(buf, offset, 0);
        int pos = name.offset;
        if (pos + 10 > buf.length) throw new DnsParseError("DNS record header is truncated.");
        int rdlen = u16(buf, pos + 8);
        pos += 10 + rdlen;
        if (pos > buf.length) throw new DnsParseError("DNS record data is truncated.");
        return pos;
    }

    private static String rdata(byte[] buf, int offset, int rdlen, int type) {
        int end = offset + rdlen;
        if (type == 1 && rdlen == 4) {
            return (buf[offset] & 0xff) + "." + (buf[offset + 1] & 0xff) + "." + (buf[offset + 2] & 0xff) + "." + (buf[offset + 3] & 0xff);
        }
        if (type == 28 && rdlen == 16) return formatIpv6(buf, offset);
        if (type == 5 || type == 2) return readName(buf, offset, 0).name;
        if (type == 15 && rdlen >= 3) {
            int pref = u16(buf, offset);
            return pref + " " + readName(buf, offset + 2, 0).name;
        }
        if (type == 16) return txt(buf, offset, end);
        if (type == 6) return soa(buf, offset, end);
        if (type == 65) return httpsRecord(buf, offset, end);
        return hex(buf, offset, rdlen);
    }

    private static String txt(byte[] buf, int offset, int end) {
        StringBuilder parts = new StringBuilder();
        int i = offset;
        while (i < end) {
            int n = buf[i] & 0xff;
            i += 1;
            if (i + n > end) break;
            parts.append(ascii(buf, i, n));
            i += n;
        }
        String text = parts.toString();
        return text.length() > 280 ? text.substring(0, 280) + "…" : text;
    }

    private static String soa(byte[] buf, int offset, int end) {
        Name mname = readName(buf, offset, 0);
        Name rname = readName(buf, mname.offset, 0);
        String serial = rname.offset + 4 <= end ? String.valueOf(u32(buf, rname.offset)) : "";
        return (mname.name + " " + rname.name + " " + serial).trim();
    }

    private static String httpsRecord(byte[] buf, int offset, int end) {
        if (end - offset < 2) return "";
        int priority = u16(buf, offset);
        Name target = readName(buf, offset + 2, 0);
        List<String> params = new ArrayList<String>();
        int pos = target.offset;
        while (pos + 4 <= end) {
            int key = u16(buf, pos);
            int len = u16(buf, pos + 2);
            pos += 4;
            if (pos + len > end) break;
            if (key == 1) params.add("alpn=" + characterStrings(buf, pos, pos + len));
            else if (key == 3 && len == 2) params.add("port=" + u16(buf, pos));
            else if (key == 4) params.add("ipv4hint=" + chunks4(buf, pos, len));
            else if (key == 6) params.add("ipv6hint=" + chunks6(buf, pos, len));
            else params.add("key" + key);
            pos += len;
        }
        StringBuilder out = new StringBuilder();
        out.append(priority).append(' ');
        out.append(target.name.length() == 0 ? "." : target.name);
        for (int i = 0; i < params.size(); i++) out.append(' ').append(params.get(i));
        return out.toString();
    }

    private static String characterStrings(byte[] buf, int offset, int end) {
        StringBuilder parts = new StringBuilder();
        int i = offset;
        while (i < end) {
            int n = buf[i] & 0xff;
            i += 1;
            if (i + n > end) break;
            if (parts.length() > 0) parts.append(',');
            parts.append(ascii(buf, i, n));
            i += n;
        }
        return parts.toString();
    }

    private static String chunks4(byte[] buf, int offset, int len) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i + 4 <= len; i += 4) {
            if (out.length() > 0) out.append(',');
            int o = offset + i;
            out.append(buf[o] & 0xff).append('.').append(buf[o + 1] & 0xff).append('.').append(buf[o + 2] & 0xff).append('.').append(buf[o + 3] & 0xff);
        }
        return out.toString();
    }

    private static String chunks6(byte[] buf, int offset, int len) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i + 16 <= len; i += 16) {
            if (out.length() > 0) out.append(',');
            out.append(formatIpv6(buf, offset + i));
        }
        return out.toString();
    }

    private static String formatIpv6(byte[] bytes, int offset) {
        String[] parts = new String[8];
        for (int i = 0; i < 8; i++) parts[i] = Integer.toHexString(u16(bytes, offset + i * 2));
        int best = -1;
        int bestLen = 0;
        int start = -1;
        for (int i = 0; i <= parts.length; i++) {
            if (i < parts.length && "0".equals(parts[i])) {
                if (start < 0) start = i;
            } else if (start >= 0) {
                int len = i - start;
                if (len > bestLen) {
                    best = start;
                    bestLen = len;
                }
                start = -1;
            }
        }
        if (bestLen < 2) return join(parts, 0, parts.length);
        return join(parts, 0, best) + "::" + join(parts, best + bestLen, parts.length);
    }

    private static String join(String[] parts, int from, int to) {
        StringBuilder out = new StringBuilder();
        for (int i = from; i < to; i++) {
            if (i > from) out.append(':');
            out.append(parts[i]);
        }
        return out.toString();
    }

    private static String hex(byte[] buf, int offset, int len) {
        int n = Math.min(len, 24);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int v = buf[offset + i] & 0xff;
            if (v < 16) out.append('0');
            out.append(Integer.toHexString(v));
        }
        if (len > n) out.append('…');
        return out.toString();
    }

    private static String ascii(byte[] buf, int offset, int len) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < len; i++) s.append((char) (buf[offset + i] & 0xff));
        return s.toString();
    }

    private static int u16(byte[] buf, int o) {
        return ((buf[o] & 0xff) << 8) | (buf[o + 1] & 0xff);
    }

    private static long u32(byte[] buf, int o) {
        return ((long) (buf[o] & 0xff) << 24)
                | ((long) (buf[o + 1] & 0xff) << 16)
                | ((long) (buf[o + 2] & 0xff) << 8)
                | (buf[o + 3] & 0xff);
    }

    private static void put16(byte[] buf, int o, int v) {
        buf[o] = (byte) ((v >> 8) & 0xff);
        buf[o + 1] = (byte) (v & 0xff);
    }

    private static boolean bit(int flags, int n) {
        return ((flags >> n) & 1) == 1;
    }
}
