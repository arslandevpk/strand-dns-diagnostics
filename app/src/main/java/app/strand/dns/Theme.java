package app.strand.dns;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;

public final class Theme {
    public final boolean light;
    public final int background;
    public final int surface;
    public final int surfaceAlt;
    public final int foreground;
    public final int muted;
    public final int line;
    public final int signal;
    public final int signalInk;
    public final int fault;
    public final int warning;

    public final Typeface sans;
    public final Typeface sansMed;
    public final Typeface sansSemi;
    public final Typeface mono;
    public final Typeface monoMed;
    private final float density;

    public Theme(Context context, String appearance) {
        density = context.getResources().getDisplayMetrics().density;
        int night = context.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        light = "light".equals(appearance)
            || ("system".equals(appearance) && night != Configuration.UI_MODE_NIGHT_YES);
        background = light ? 0xFFF2F4EA : 0xFF10120E;
        surface = light ? 0xFFFCFDF7 : 0xFF1C2118;
        surfaceAlt = light ? 0xFFE2E9D8 : 0xFF262C20;
        foreground = light ? 0xFF20271A : 0xFFF3F4EC;
        muted = light ? 0xFF505A47 : 0xFF9AA390;
        line = light ? 0xFFC0CBB7 : 0xFF343B2C;
        signal = light ? 0xFF496520 : 0xFFD2F25C;
        signalInk = light ? 0xFFFFFFFF : 0xFF17200A;
        fault = light ? 0xFFAD381F : 0xFFFF6A45;
        warning = light ? 0xFF79570E : 0xFFE6C36A;
        Typeface regular = font(context, "fonts/Hack-Regular.ttf", Typeface.MONOSPACE);
        Typeface bold = font(context, "fonts/Hack-Bold.ttf", Typeface.DEFAULT_BOLD);
        sans = regular;
        sansMed = bold;
        sansSemi = bold;
        mono = regular;
        monoMed = bold;
    }

    public int dp(int value) {
        return Math.round(value * density);
    }

    public int tone(String verdict) {
        if ("up".equals(verdict)) return signal;
        if ("degraded".equals(verdict)) return warning;
        return fault;
    }

    public GradientDrawable rounded(int fill, int stroke, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radiusDp));
        if (stroke != 0) drawable.setStroke(Math.max(1, dp(1)), stroke);
        return drawable;
    }

    public GradientDrawable pill(int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(0x00000000);
        drawable.setCornerRadius(dp(999));
        drawable.setStroke(Math.max(1, dp(1)), stroke);
        return drawable;
    }

    public GradientDrawable circleStroke() {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.OVAL);
        drawable.setColor(0x00000000);
        drawable.setStroke(Math.max(1, dp(1)), line);
        return drawable;
    }

    private static Typeface font(Context context, String path, Typeface fallback) {
        try {
            Typeface face = Typeface.createFromAsset(context.getAssets(), path);
            if (face != null) return face;
        } catch (RuntimeException ignored) {
            // A missing asset still leaves the screen readable.
        }
        return fallback;
    }
}
