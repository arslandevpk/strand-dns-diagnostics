package app.strand.dns;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class ReportView {
    private ReportView() {}

    public static View compact(Context context, Theme theme, Models.ProbeResult result, final Runnable openDiagnostics) {
        LinearLayout box = Ui.column(context);
        box.setPadding(0, theme.dp(16), 0, 0);
        View rule = new View(context);
        rule.setBackgroundColor(theme.line);
        box.addView(rule, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Math.max(1, theme.dp(1))));

        TextView headline = Ui.text(context, theme, Present.headlineOf(result), 24, theme.tone(result.verdict), theme.sansMed);
        Ui.softWrap(headline);
        box.addView(headline, Ui.matchTop(theme.dp(16)));

        LinearLayout meta = Ui.row(context, Gravity.CENTER_VERTICAL);
        meta.addView(pill(context, theme, result.verdict));
        TextView ms = Ui.text(context, theme, result.timing.totalMs + " ms", 14, theme.muted, theme.mono);
        LinearLayout.LayoutParams msLp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        msLp.leftMargin = theme.dp(8);
        meta.addView(ms, msLp);
        TextView query = Ui.text(context, theme, result.queryName + " · " + result.qtype, 14, theme.muted, theme.sans);
        LinearLayout.LayoutParams queryLp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        queryLp.leftMargin = theme.dp(8);
        meta.addView(query, queryLp);
        box.addView(meta, Ui.matchTop(theme.dp(8)));

        TextView summary = Ui.text(context, theme, result.summary, 14, theme.muted, theme.sans);
        Ui.softWrap(summary);
        box.addView(summary, Ui.matchTop(theme.dp(8)));

        if (result.dns != null && result.dns.answers.size() > 1) {
            LinearLayout answers = Ui.column(context);
            int n = Math.min(4, result.dns.answers.size());
            for (int i = 0; i < n; i++) answers.addView(answerLine(context, theme, result.dns.answers.get(i), false));
            box.addView(answers, Ui.matchTop(theme.dp(12)));
        }

        String note = result.note != null ? result.note : ("doh".equals(result.protocol) ? "From this device" : "From this device");
        TextView noteView = Ui.text(context, theme, note, 12, theme.muted, theme.sans);
        Ui.softWrap(noteView);
        box.addView(noteView, Ui.matchTop(theme.dp(12)));

        TextView open = Ui.text(context, theme, "Open diagnostics", 14, theme.foreground, theme.sans);
        open.setMinimumHeight(theme.dp(44));
        open.setGravity(Gravity.CENTER_VERTICAL);
        open.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                openDiagnostics.run();
            }
        });
        box.addView(open, Ui.matchTop(theme.dp(4)));
        return box;
    }

    public static View full(Context context, Theme theme, Models.ProbeResult result) {
        LinearLayout box = Ui.column(context);
        String proto = "doh".equals(result.protocol) ? "DNS over HTTPS" : "DNS over TLS";
        box.addView(Ui.eyebrow(context, theme, proto + " · " + result.host));

        TextView headline = Ui.text(context, theme, Present.headlineOf(result), 30, theme.tone(result.verdict), theme.sansMed);
        Ui.softWrap(headline);
        box.addView(headline, Ui.matchTop(theme.dp(8)));

        LinearLayout meta = Ui.row(context, Gravity.CENTER_VERTICAL);
        meta.addView(pill(context, theme, result.verdict));
        TextView ms = Ui.text(context, theme, result.timing.totalMs + " ms", 14, theme.muted, theme.mono);
        LinearLayout.LayoutParams msLp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        msLp.leftMargin = theme.dp(8);
        meta.addView(ms, msLp);
        box.addView(meta, Ui.matchTop(theme.dp(12)));

        TextView summary = Ui.text(context, theme, result.summary, 14, theme.foreground, theme.sans);
        Ui.softWrap(summary);
        box.addView(summary, Ui.matchTop(theme.dp(12)));

        TextView query = Ui.text(context, theme, result.queryName + " · " + result.qtype + " · From this device", 14, theme.muted, theme.sans);
        Ui.softWrap(query);
        box.addView(query, Ui.matchTop(theme.dp(4)));
        if (result.note != null) {
            TextView note = Ui.text(context, theme, result.note, 14, theme.muted, theme.sans);
            Ui.softWrap(note);
            box.addView(note, Ui.matchTop(theme.dp(8)));
        }

        box.addView(stages(context, theme, result), Ui.matchTop(theme.dp(20)));
        if (result.dns != null) box.addView(dnsBlock(context, theme, result.dns), Ui.matchTop(theme.dp(8)));
        if (result.certificate != null && result.certificate.fingerprint256.length() > 0) {
            box.addView(certBlock(context, theme, result.certificate), Ui.matchTop(theme.dp(20)));
        }
        return box;
    }

    public static View pairButton(Context context, Theme theme, String label, Models.ProbeResult result, boolean active, final Runnable onClick) {
        LinearLayout box = Ui.column(context);
        box.setBackground(theme.rounded(theme.surface, active ? theme.signal : theme.line, 20));
        box.setPadding(theme.dp(12), theme.dp(12), theme.dp(12), theme.dp(12));
        box.addView(Ui.text(context, theme, label, 12, theme.muted, theme.sans));
        LinearLayout.LayoutParams pillLp = Ui.matchTop(theme.dp(8));
        box.addView(pill(context, theme, result.verdict), pillLp);
        box.addView(Ui.text(context, theme, result.timing.totalMs + " ms", 12, theme.muted, theme.mono), Ui.matchTop(theme.dp(8)));
        box.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                onClick.run();
            }
        });
        return box;
    }

    public static View historyRow(Context context, Theme theme, Models.ProbeResult result, final Runnable onClick) {
        LinearLayout row = Ui.row(context, Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(theme.dp(64));
        row.setPadding(0, theme.dp(12), 0, theme.dp(12));
        row.addView(pill(context, theme, result.verdict));
        LinearLayout text = Ui.column(context);
        TextView headline = Ui.text(context, theme, Present.headlineOf(result), 14, theme.foreground, theme.sans);
        Ui.ellipsize(headline);
        text.addView(headline);
        String proto = "doh".equals(result.protocol) ? "DoH" : "DoT";
        TextView sub = Ui.text(context, theme, proto + " · " + result.host + " · " + result.queryName, 12, theme.muted, theme.sans);
        Ui.ellipsize(sub);
        text.addView(sub, Ui.matchTop(theme.dp(4)));
        LinearLayout.LayoutParams textLp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        textLp.leftMargin = theme.dp(12);
        textLp.rightMargin = theme.dp(12);
        row.addView(text, textLp);
        row.addView(Ui.text(context, theme, result.timing.totalMs + " ms", 12, theme.muted, theme.mono));
        row.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                onClick.run();
            }
        });
        return row;
    }

    private static View stages(Context context, Theme theme, Models.ProbeResult result) {
        LinearLayout list = Ui.column(context);
        for (int i = 0; i < result.stages.size(); i++) {
            Models.Stage stage = result.stages.get(i);
            LinearLayout row = Ui.row(context, Gravity.TOP);
            LinearLayout rail = Ui.column(context);
            rail.setGravity(Gravity.CENTER_HORIZONTAL);
            View dot = new View(context);
            GradientDrawable circle = new GradientDrawable();
            circle.setShape(GradientDrawable.OVAL);
            int color = theme.line;
            if ("ok".equals(stage.state)) color = theme.signal;
            else if ("fail".equals(stage.state)) color = theme.fault;
            circle.setColor(color);
            rail.addView(dot, new LinearLayout.LayoutParams(theme.dp(10), theme.dp(10)));
            if (i < result.stages.size() - 1) {
                View line = new View(context);
                line.setBackgroundColor(theme.line);
                LinearLayout.LayoutParams lineLp = new LinearLayout.LayoutParams(Math.max(1, theme.dp(1)), theme.dp(28));
                lineLp.topMargin = theme.dp(4);
                rail.addView(line, lineLp);
            }
            row.addView(rail, new LinearLayout.LayoutParams(theme.dp(16), LinearLayout.LayoutParams.WRAP_CONTENT));
            LinearLayout body = Ui.column(context);
            LinearLayout top = Ui.row(context, Gravity.CENTER_VERTICAL);
            TextView label = Ui.text(context, theme, stage.label, 14, theme.foreground, theme.sans);
            top.addView(label, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            if (stage.ms != null) top.addView(Ui.text(context, theme, stage.ms + " ms", 12, theme.muted, theme.mono));
            body.addView(top);
            TextView detail = Ui.text(context, theme, stage.detail, 14, theme.muted, theme.sans);
            Ui.softWrap(detail);
            body.addView(detail, Ui.matchTop(theme.dp(2)));
            LinearLayout.LayoutParams bodyLp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            bodyLp.bottomMargin = theme.dp(16);
            row.addView(body, bodyLp);
            list.addView(row, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        }
        return list;
    }

    private static View dnsBlock(Context context, Theme theme, Models.DnsView dns) {
        LinearLayout box = Ui.column(context);
        box.addView(Ui.text(context, theme, "Answer", 14, theme.foreground, theme.sansMed));
        LinearLayout flags = Ui.row(context, Gravity.CENTER_VERTICAL);
        flags.addView(flag(context, theme, "RA", dns.ra));
        flags.addView(flag(context, theme, "AD", dns.ad));
        flags.addView(flag(context, theme, "AA", dns.aa));
        flags.addView(flag(context, theme, "TC", dns.tc));
        flags.addView(flag(context, theme, "RD", dns.rd));
        flags.addView(flag(context, theme, "CD", dns.cd));
        box.addView(flags, Ui.matchTop(theme.dp(8)));
        if (dns.answers.size() == 0) {
            TextView empty = Ui.text(context, theme, "No answer records. Authority section had " + dns.authorityCount + ".", 14, theme.muted, theme.sans);
            Ui.softWrap(empty);
            box.addView(empty, Ui.matchTop(theme.dp(12)));
            return box;
        }
        LinearLayout list = Ui.column(context);
        View top = new View(context);
        top.setBackgroundColor(theme.line);
        list.addView(top, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Math.max(1, theme.dp(1))));
        for (int i = 0; i < dns.answers.size(); i++) {
            LinearLayout row = Ui.row(context, Gravity.TOP);
            row.setPadding(0, theme.dp(12), 0, theme.dp(12));
            LinearLayout kind = Ui.column(context);
            kind.addView(Ui.text(context, theme, dns.answers.get(i).type, 12, theme.muted, theme.mono));
            kind.addView(Ui.text(context, theme, dns.answers.get(i).ttl + "s", 12, theme.muted, theme.mono), Ui.matchTop(theme.dp(4)));
            row.addView(kind, new LinearLayout.LayoutParams(theme.dp(64), LinearLayout.LayoutParams.WRAP_CONTENT));
            TextView data = Ui.text(context, theme, dns.answers.get(i).data, 14, theme.foreground, theme.mono);
            Ui.softWrap(data);
            row.addView(data, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            list.addView(row);
            View rule = new View(context);
            rule.setBackgroundColor(theme.line);
            list.addView(rule, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Math.max(1, theme.dp(1))));
        }
        box.addView(list, Ui.matchTop(theme.dp(12)));
        return box;
    }

    private static View certBlock(Context context, Theme theme, Models.CertInfo cert) {
        LinearLayout box = Ui.column(context);
        box.addView(Ui.text(context, theme, "Certificate", 14, theme.foreground, theme.sansMed));
        box.addView(certRow(context, theme, "Subject", cert.subject.length() == 0 ? "—" : cert.subject, false), Ui.matchTop(theme.dp(8)));
        box.addView(certRow(context, theme, "Issuer", cert.issuer.length() == 0 ? "—" : cert.issuer, false), Ui.matchTop(theme.dp(8)));
        String trust = cert.authorized ? "Trusted" : (cert.error == null ? "Not trusted" : cert.error);
        box.addView(certRow(context, theme, "Trust", trust, false), Ui.matchTop(theme.dp(8)));
        box.addView(certRow(context, theme, "Remaining", cert.daysRemaining + " days", false), Ui.matchTop(theme.dp(8)));
        box.addView(certRow(context, theme, "Fingerprint", cert.fingerprint256, true), Ui.matchTop(theme.dp(8)));
        return box;
    }

    private static View certRow(Context context, Theme theme, String label, String value, boolean mono) {
        LinearLayout row = Ui.row(context, Gravity.TOP);
        TextView name = Ui.text(context, theme, label, 14, theme.muted, theme.sans);
        row.addView(name, new LinearLayout.LayoutParams(theme.dp(96), LinearLayout.LayoutParams.WRAP_CONTENT));
        TextView data = Ui.text(context, theme, value, mono ? 12 : 14, theme.foreground, mono ? theme.mono : theme.sans);
        Ui.softWrap(data);
        row.addView(data, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private static View answerLine(Context context, Theme theme, Models.Answer answer, boolean unused) {
        LinearLayout row = Ui.row(context, Gravity.TOP);
        TextView type = Ui.text(context, theme, answer.type, 12, theme.muted, theme.mono);
        row.addView(type, new LinearLayout.LayoutParams(theme.dp(56), LinearLayout.LayoutParams.WRAP_CONTENT));
        TextView data = Ui.text(context, theme, answer.data, 12, theme.foreground, theme.mono);
        Ui.softWrap(data);
        row.addView(data, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        LinearLayout.LayoutParams lp = Ui.match();
        lp.topMargin = theme.dp(4);
        row.setLayoutParams(lp);
        return row;
    }

    private static TextView pill(Context context, Theme theme, String verdict) {
        int color = theme.tone(verdict);
        TextView view = Ui.text(context, theme, Present.verdictLabel(verdict), 12, color, theme.sans);
        view.setGravity(Gravity.CENTER);
        view.setMinimumHeight(theme.dp(28));
        view.setPadding(theme.dp(10), 0, theme.dp(10), 0);
        view.setBackground(theme.pill(color));
        return view;
    }

    private static TextView flag(Context context, Theme theme, String label, boolean on) {
        TextView view = Ui.text(context, theme, label, 12, on ? theme.signal : theme.muted, theme.mono);
        view.setPadding(theme.dp(8), theme.dp(4), theme.dp(8), theme.dp(4));
        view.setBackground(theme.pill(on ? theme.signal : theme.line));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.rightMargin = theme.dp(6);
        view.setLayoutParams(lp);
        return view;
    }
}
