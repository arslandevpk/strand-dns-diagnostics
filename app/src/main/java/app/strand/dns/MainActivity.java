package app.strand.dns;

import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.Dialog;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final String[] APPEARANCE_VALUES = {"system", "light", "dark"};
    private static final String[] APPEARANCE_LABELS = {"System default", "Light", "Dark"};

    private Theme theme;
    private String appearance;
    private ValueAnimator openingProgress;
    private Store store;
    private Models.Session session;
    private ExecutorService executor;
    private FormView homeForm;
    private FormView diagForm;
    private LinearLayout homeResults;
    private LinearLayout diagPair;
    private LinearLayout diagReport;
    private LinearLayout diagEmpty;
    private LinearLayout diagHistory;
    private View statusBar;
    private GradientDrawable statusDrawable;
    private ScrollView homeScroll;
    private ScrollView diagScroll;
    private boolean busy;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        appearance = getPreferences(MODE_PRIVATE).getString("appearance", "system");
        theme = new Theme(this, appearance);
        store = new Store(this);
        session = store.load();
        executor = Executors.newSingleThreadExecutor();
        getWindow().setStatusBarColor(theme.background);
        getWindow().setNavigationBarColor(Build.VERSION.SDK_INT >= 26 ? theme.background : 0xFF10120E);
        int flags = getWindow().getDecorView().getSystemUiVisibility();
        int lightBars = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        if (Build.VERSION.SDK_INT >= 26) lightBars |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        getWindow().getDecorView().setSystemUiVisibility(theme.light ? flags | lightBars : flags & ~lightBars);

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(theme.background);
        homeScroll = page(false);
        diagScroll = page(true);
        FrameLayout screens = new FrameLayout(this);
        screens.addView(homeScroll);
        screens.addView(diagScroll);
        root.addView(screens);
        setContentView(root);
        showScreen(session.screen, false);
        refresh();
        if (savedInstanceState == null) animateOpening(root, screens);
    }

    @Override
    protected void onDestroy() {
        if (openingProgress != null) openingProgress.cancel();
        super.onDestroy();
    }

    @Override
    protected void onPause() {
        super.onPause();
        store.save(session);
    }

    @Override
    public void onBackPressed() {
        if ("diagnostics".equals(session.screen)) {
            showScreen("home", true);
            return;
        }
        super.onBackPressed();
    }

    private void showAppearance() {
        Dialog dialog = new Dialog(this);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        LinearLayout options = card();
        options.addView(Ui.text(this, theme, "Appearance", 16, theme.foreground, theme.sansMed));
        for (int i = 0; i < APPEARANCE_VALUES.length; i++) {
            final String value = APPEARANCE_VALUES[i];
            boolean selected = value.equals(appearance);
            TextView option = Ui.text(this, theme, APPEARANCE_LABELS[i], 14,
                    selected ? theme.signal : theme.foreground, theme.sans);
            option.setGravity(Gravity.CENTER_VERTICAL);
            option.setMinHeight(theme.dp(48));
            option.setPadding(theme.dp(12), 0, theme.dp(12), 0);
            option.setSelected(selected);
            if (selected) option.setBackground(theme.rounded(theme.surfaceAlt, 0, 12));
            option.setOnClickListener(v -> {
                dialog.dismiss();
                if (value.equals(appearance)) return;
                getPreferences(MODE_PRIVATE).edit().putString("appearance", value).apply();
                store.save(session);
                recreate();
            });
            options.addView(option, Ui.matchTop(theme.dp(4)));
        }
        dialog.setContentView(options);
        dialog.show();
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            window.setLayout(Math.min(theme.dp(320), getResources().getDisplayMetrics().widthPixels - theme.dp(40)),
                    LinearLayout.LayoutParams.WRAP_CONTENT);
        }
    }

    private void animateOpening(FrameLayout root, FrameLayout screens) {
        if (Build.VERSION.SDK_INT >= 26 && !ValueAnimator.areAnimatorsEnabled()) return;
        FrameLayout overlay = new FrameLayout(this);
        overlay.setBackgroundColor(theme.background);
        overlay.setClickable(true);
        LinearLayout content = Ui.column(this);
        content.setGravity(Gravity.CENTER_HORIZONTAL);
        content.setAlpha(0f);
        content.setScaleX(0.92f);
        content.setScaleY(0.92f);

        ImageView icon = new ImageView(this);
        icon.setImageResource(R.mipmap.ic_launcher_round);
        content.addView(icon, new LinearLayout.LayoutParams(theme.dp(72), theme.dp(72)));
        TextView title = Ui.text(this, theme, getString(R.string.app_name), 32, theme.foreground, theme.sansMed);
        title.setGravity(Gravity.CENTER);
        content.addView(title, Ui.matchTop(theme.dp(16)));

        FrameLayout track = new FrameLayout(this);
        track.setBackground(theme.rounded(theme.line, 0, 4));
        View fill = new View(this);
        fill.setBackground(theme.rounded(theme.signal, 0, 4));
        track.addView(fill, new FrameLayout.LayoutParams(theme.dp(2), theme.dp(4)));
        int trackWidth = theme.dp(144);
        LinearLayout.LayoutParams trackParams = new LinearLayout.LayoutParams(trackWidth, theme.dp(4));
        trackParams.topMargin = theme.dp(22);
        content.addView(track, trackParams);
        TextView percent = Ui.text(this, theme, "1%", 13, theme.muted, theme.mono);
        percent.setGravity(Gravity.CENTER);
        content.addView(percent, Ui.matchTop(theme.dp(10)));

        int wrap = FrameLayout.LayoutParams.WRAP_CONTENT;
        overlay.addView(content, new FrameLayout.LayoutParams(wrap, wrap, Gravity.CENTER));
        root.addView(overlay);
        screens.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        content.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(260)
            .setInterpolator(new AccelerateDecelerateInterpolator()).withEndAction(() -> {
                if (isDestroyed()) return;
                openingProgress = ValueAnimator.ofInt(1, 100);
                openingProgress.setDuration(470);
                openingProgress.setInterpolator(new LinearInterpolator());
                openingProgress.addUpdateListener(animation -> {
                    int value = (int) animation.getAnimatedValue();
                    percent.setText(value + "%");
                    FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) fill.getLayoutParams();
                    params.width = Math.max(theme.dp(2), trackWidth * value / 100);
                    fill.setLayoutParams(params);
                    if (value != 100) return;
                    content.animate().alpha(0f).scaleX(1.04f).scaleY(1.04f).setDuration(210).start();
                    overlay.animate().alpha(0f).setStartDelay(75).setDuration(280).withEndAction(() -> {
                        root.removeView(overlay);
                        screens.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_AUTO);
                    }).start();
                });
                openingProgress.start();
            }).start();
    }

    private ScrollView page(boolean diagnostics) {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(theme.background);
        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.setGravity(Gravity.CENTER_HORIZONTAL);
        outer.setPadding(theme.dp(20), theme.dp(diagnostics ? 32 : 56), theme.dp(20), theme.dp(48));
        int screen = getResources().getDisplayMetrics().widthPixels;
        int max = theme.dp(diagnostics ? 512 : 448);
        int inner = Math.min(screen - theme.dp(40), max);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        if (diagnostics) buildDiagnostics(column);
        else buildHome(column);
        outer.addView(column, new LinearLayout.LayoutParams(inner, LinearLayout.LayoutParams.WRAP_CONTENT));
        scroll.addView(outer);
        return scroll;
    }

    private void buildHome(LinearLayout column) {
        LinearLayout card = card();
        statusDrawable = new GradientDrawable();
        statusDrawable.setCornerRadius(theme.dp(99));
        statusDrawable.setColor(theme.line);
        statusBar = new View(this);
        statusBar.setBackground(statusDrawable);
        card.addView(statusBar, new LinearLayout.LayoutParams(theme.dp(40), theme.dp(4)));
        homeForm = new FormView(this, theme, false, listener);
        card.addView(homeForm, Ui.matchTop(theme.dp(16)));
        homeResults = Ui.column(this);
        card.addView(homeResults);
        column.addView(card);

        LinearLayout dock = Ui.column(this);
        dock.setGravity(Gravity.CENTER_HORIZONTAL);
        FrameLayout markBox = new FrameLayout(this);
        markBox.setBackground(theme.rounded(theme.surface, theme.line, 16));
        Ui.MarkView mark = new Ui.MarkView(this, theme.signal);
        FrameLayout.LayoutParams markLp = new FrameLayout.LayoutParams(theme.dp(24), theme.dp(24), Gravity.CENTER);
        markBox.addView(mark, markLp);
        dock.addView(markBox, new LinearLayout.LayoutParams(theme.dp(56), theme.dp(56)));
        TextView label = Ui.text(this, theme, "Diagnostics", 12, theme.muted, theme.sans);
        label.setGravity(Gravity.CENTER);
        dock.addView(label, Ui.matchTop(theme.dp(8)));
        dock.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showScreen("diagnostics", true);
            }
        });
        dock.setContentDescription("Diagnostics");
        LinearLayout.LayoutParams dockLp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        dockLp.topMargin = theme.dp(32);
        column.addView(dock, dockLp);
    }

    private void buildDiagnostics(LinearLayout column) {
        LinearLayout header = Ui.row(this, Gravity.CENTER_VERTICAL);
        FrameLayout back = new FrameLayout(this);
        back.setBackground(theme.circleStroke());
        back.setContentDescription("Home");
        Ui.ChevronView chevron = new Ui.ChevronView(this, theme.foreground);
        FrameLayout.LayoutParams chevronLp = new FrameLayout.LayoutParams(theme.dp(22), theme.dp(22), Gravity.CENTER);
        back.addView(chevron, chevronLp);
        back.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                showScreen("home", true);
            }
        });
        header.addView(back, new LinearLayout.LayoutParams(theme.dp(44), theme.dp(44)));
        LinearLayout titles = Ui.column(this);
        titles.addView(Ui.eyebrow(this, theme, "STRAND DNS"));
        TextView title = Ui.text(this, theme, "Diagnostics", 20, theme.foreground, theme.sansMed);
        titles.addView(title, Ui.matchTop(theme.dp(2)));
        LinearLayout.LayoutParams titlesLp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        titlesLp.leftMargin = theme.dp(12);
        header.addView(titles, titlesLp);
        TextView appearanceButton = Ui.text(this, theme, "Theme", 12, theme.muted, theme.sans);
        appearanceButton.setGravity(Gravity.CENTER);
        appearanceButton.setMinHeight(theme.dp(44));
        appearanceButton.setPadding(theme.dp(10), 0, theme.dp(10), 0);
        appearanceButton.setBackground(theme.rounded(theme.surface, theme.line, 14));
        appearanceButton.setContentDescription("Appearance");
        appearanceButton.setOnClickListener(v -> showAppearance());
        header.addView(appearanceButton);
        column.addView(header);

        LinearLayout card = card();
        diagForm = new FormView(this, theme, true, listener);
        card.addView(diagForm);
        column.addView(card, Ui.matchTop(theme.dp(24)));

        diagPair = Ui.row(this, Gravity.CENTER_VERTICAL);
        diagPair.setVisibility(View.GONE);
        column.addView(diagPair, Ui.matchTop(theme.dp(16)));

        diagReport = card();
        diagReport.setVisibility(View.GONE);
        column.addView(diagReport, Ui.matchTop(theme.dp(16)));

        diagEmpty = Ui.column(this);
        TextView empty = Ui.text(this, theme, "A check is up only when the encrypted session returns a DNS message for the name you asked. NXDOMAIN still counts: the resolver answered. Timeout, a bad certificate, or a broken reply does not.", 14, theme.muted, theme.sans);
        Ui.softWrap(empty);
        diagEmpty.addView(empty);
        column.addView(diagEmpty, Ui.matchTop(theme.dp(24)));

        diagHistory = Ui.column(this);
        column.addView(diagHistory, Ui.matchTop(theme.dp(32)));
    }

    private final FormView.Listener listener = new FormView.Listener() {
        public void onEndpoint(FormView source, String value) {
            session.endpoint = value;
            other(source).setResolverQuiet(value);
            store.save(session);
        }

        public void onName(FormView source, String value) {
            session.name = value;
            other(source).setNameQuiet(value);
            store.save(session);
        }

        public void onProtocol(String protocol) {
            session.setProtocol(protocol);
            homeForm.reflect(session);
            diagForm.reflect(session);
            store.save(session);
        }

        public void onQtype(String qtype) {
            session.qtype = qtype;
            homeForm.reflect(session);
            diagForm.reflect(session);
            store.save(session);
        }

        public void onStrict(boolean strict) {
            session.strict = strict;
            homeForm.reflect(session);
            diagForm.reflect(session);
            store.save(session);
        }

        public void onPreset(Endpoints.Preset preset) {
            session.applyPreset(preset);
            homeForm.reflect(session);
            diagForm.reflect(session);
            store.save(session);
        }

        public void onCheck(FormView source) {
            source.showError(null);
            other(source).showError(null);
            runSingle();
        }

        public void onCheckBoth(FormView source) {
            Endpoints.Both both = Endpoints.bothEndpoints(session.endpoint, session.protocol);
            if (both.error != null) {
                source.showError(both.error);
                return;
            }
            source.showError(null);
            other(source).showError(null);
            runBoth(both);
        }
    };

    private FormView other(FormView source) {
        return source == homeForm ? diagForm : homeForm;
    }

    private void runSingle() {
        if (busy) return;
        if (!online()) {
            finishWith(Present.failure(session.protocol, session.qtype, session.endpoint, "", session.name, "This device is offline.", "offline", 0, null), null, null);
            return;
        }
        final Models.CheckInput input = snapshot();
        setBusy(true);
        executor.execute(new Runnable() {
            public void run() {
                final Models.ProbeResult result = Probe.run(input);
                deliver(result, null, null);
            }
        });
    }

    private void runBoth(final Endpoints.Both both) {
        if (busy) return;
        if (!online()) {
            finishWith(Present.failure(session.protocol, session.qtype, session.endpoint, "", session.name, "This device is offline.", "offline", 0, null), null, null);
            return;
        }
        final Models.CheckInput base = snapshot();
        setBusy(true);
        executor.execute(new Runnable() {
            public void run() {
                final Models.ProbeResult[] out = new Models.ProbeResult[2];
                Thread doh = new Thread(new Runnable() {
                    public void run() {
                        out[0] = Probe.run(base.withProtocol("doh", both.doh));
                    }
                });
                Thread dot = new Thread(new Runnable() {
                    public void run() {
                        out[1] = Probe.run(base.withProtocol("dot", both.dot));
                    }
                });
                doh.start();
                dot.start();
                try {
                    doh.join();
                    dot.join();
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                }
                Models.ProbeResult primary = "dot".equals(base.protocol) ? out[1] : out[0];
                if (primary == null) {
                    primary = Present.failure(base.protocol, base.qtype, base.endpoint, "", base.name, "The check failed.", "error", 0, null);
                }
                deliver(primary, out[0], out[1]);
            }
        });
    }

    private void deliver(final Models.ProbeResult primary, final Models.ProbeResult doh, final Models.ProbeResult dot) {
        runOnUiThread(new Runnable() {
            public void run() {
                if (isDestroyed()) return;
                finishWith(primary, doh, dot);
            }
        });
    }

    private void finishWith(Models.ProbeResult primary, Models.ProbeResult doh, Models.ProbeResult dot) {
        busy = false;
        session.remember(primary, doh, dot);
        store.save(session);
        refresh();
    }

    private void setBusy(boolean value) {
        busy = value;
        homeForm.setBusy(value, session.primary != null);
        diagForm.setBusy(value, session.primary != null);
        paintStatus();
    }

    private Models.CheckInput snapshot() {
        return new Models.CheckInput(session.protocol, session.endpoint, session.name, session.qtype, session.strict, 8000);
    }

    private void refresh() {
        homeForm.reflect(session);
        diagForm.reflect(session);
        homeForm.setBusy(busy, session.primary != null);
        diagForm.setBusy(busy, session.primary != null);
        paintStatus();
        homeResults.removeAllViews();
        if (session.primary != null) {
            homeResults.addView(ReportView.compact(this, theme, session.primary, new Runnable() {
                public void run() {
                    showScreen("diagnostics", true);
                }
            }));
        }
        boolean paired = session.pairDoh != null && session.pairDot != null;
        diagPair.removeAllViews();
        if (paired) {
            diagPair.setVisibility(View.VISIBLE);
            View doh = ReportView.pairButton(this, theme, "DoH", session.pairDoh, sameResult(session.primary, session.pairDoh), new Runnable() {
                public void run() {
                    session.primary = session.pairDoh;
                    store.save(session);
                    refresh();
                }
            });
            View dot = ReportView.pairButton(this, theme, "DoT", session.pairDot, sameResult(session.primary, session.pairDot), new Runnable() {
                public void run() {
                    session.primary = session.pairDot;
                    store.save(session);
                    refresh();
                }
            });
            LinearLayout.LayoutParams left = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            LinearLayout.LayoutParams right = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            right.leftMargin = theme.dp(8);
            diagPair.addView(doh, left);
            diagPair.addView(dot, right);
        } else {
            diagPair.setVisibility(View.GONE);
        }
        diagReport.removeAllViews();
        if (session.primary != null) {
            diagReport.setVisibility(View.VISIBLE);
            diagReport.addView(ReportView.full(this, theme, session.primary));
            diagEmpty.setVisibility(View.GONE);
        } else {
            diagReport.setVisibility(View.GONE);
            diagEmpty.setVisibility(View.VISIBLE);
        }
        diagHistory.removeAllViews();
        if (session.history.size() > 0) {
            LinearLayout title = Ui.row(this, Gravity.CENTER_VERTICAL);
            TextView recent = Ui.text(this, theme, "Recent", 14, theme.foreground, theme.sans);
            title.addView(recent, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            TextView clear = Ui.text(this, theme, "Clear", 14, theme.muted, theme.sans);
            clear.setGravity(Gravity.CENTER);
            clear.setMinimumHeight(theme.dp(44));
            clear.setPadding(theme.dp(8), 0, theme.dp(8), 0);
            clear.setOnClickListener(new View.OnClickListener() {
                public void onClick(View v) {
                    session.history.clear();
                    store.save(session);
                    refresh();
                }
            });
            title.addView(clear);
            diagHistory.addView(title);
            View top = rule();
            diagHistory.addView(top, Ui.matchTop(theme.dp(4)));
            for (int i = 0; i < session.history.size(); i++) {
                final Models.ProbeResult item = session.history.get(i);
                diagHistory.addView(ReportView.historyRow(this, theme, item, new Runnable() {
                    public void run() {
                        session.openResult(item);
                        store.save(session);
                        refresh();
                    }
                }));
                diagHistory.addView(rule());
            }
        }
    }

    private boolean sameResult(Models.ProbeResult a, Models.ProbeResult b) {
        if (a == null || b == null) return false;
        return Models.Session.idOf(a).equals(Models.Session.idOf(b));
    }

    private void paintStatus() {
        int color = theme.line;
        if (busy) color = theme.signal;
        else if (session.primary != null) color = theme.tone(session.primary.verdict);
        statusDrawable.setColor(color);
        statusBar.clearAnimation();
        if (busy) {
            AlphaAnimation pulse = new AlphaAnimation(1f, 0.35f);
            pulse.setDuration(600);
            pulse.setRepeatMode(Animation.REVERSE);
            pulse.setRepeatCount(Animation.INFINITE);
            statusBar.startAnimation(pulse);
        }
    }

    private void showScreen(String screen, boolean save) {
        session.screen = screen;
        boolean diagnostics = "diagnostics".equals(screen);
        homeScroll.setVisibility(diagnostics ? View.GONE : View.VISIBLE);
        diagScroll.setVisibility(diagnostics ? View.VISIBLE : View.GONE);
        if (save) store.save(session);
    }

    private LinearLayout card() {
        LinearLayout card = Ui.column(this);
        card.setBackground(theme.rounded(theme.surface, theme.line, 28));
        card.setPadding(theme.dp(16), theme.dp(16), theme.dp(16), theme.dp(16));
        return card;
    }

    private View rule() {
        View view = new View(this);
        view.setBackgroundColor(theme.line);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Math.max(1, theme.dp(1)));
        view.setLayoutParams(lp);
        return view;
    }

    private boolean online() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm == null) return true;
        if (Build.VERSION.SDK_INT >= 23) {
            Network network = cm.getActiveNetwork();
            if (network == null) return false;
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            return caps != null;
        }
        android.net.NetworkInfo info = cm.getActiveNetworkInfo();
        return info != null && info.isConnected();
    }
}
