package app.strand.dns;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class Ui {
    private Ui() {}

    public static TextView text(Context context, Theme theme, String value, float sp, int color, android.graphics.Typeface face) {
        TextView view = new TextView(context);
        view.setText(value);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        view.setTextColor(color);
        view.setTypeface(face);
        view.setIncludeFontPadding(false);
        return view;
    }

    public static TextView eyebrow(Context context, Theme theme, String value) {
        TextView view = text(context, theme, value, 12, theme.muted, theme.sans);
        view.setLetterSpacing(0.14f);
        view.setAllCaps(false);
        return view;
    }

    public static void softWrap(TextView view) {
        view.setSingleLine(false);
        view.setEllipsize(null);
        view.setHorizontallyScrolling(false);
    }

    public static LinearLayout column(Context context) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    public static LinearLayout row(Context context, int gravity) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.HORIZONTAL);
        layout.setGravity(gravity);
        return layout;
    }

    public static LinearLayout.LayoutParams match() {
        return new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    public static LinearLayout.LayoutParams matchTop(int top) {
        LinearLayout.LayoutParams params = match();
        params.topMargin = top;
        return params;
    }

    public static class MarkView extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

        public MarkView(Context context, int color) {
            super(context);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeCap(Paint.Cap.ROUND);
            paint.setColor(color);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float w = getWidth();
            float h = getHeight();
            paint.setStrokeWidth(Math.max(2f, w * 2.4f / 32f));
            float x1 = w * 8f / 32f;
            float x2 = w * 16f / 32f;
            float x3 = w * 24f / 32f;
            float y0 = h * 6f / 32f;
            float y1 = h * 26f / 32f;
            canvas.drawLine(x1, y0, x1, y1, paint);
            canvas.drawLine(x3, y0, x3, y1, paint);
            Path curve = new Path();
            curve.moveTo(x2, y0);
            curve.cubicTo(w * 22f / 32f, h * 10f / 32f, w * 22f / 32f, h * 22f / 32f, x2, y1);
            canvas.drawPath(curve, paint);
        }
    }

    public static class ChevronView extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

        public ChevronView(Context context, int color) {
            super(context);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeCap(Paint.Cap.ROUND);
            paint.setStrokeJoin(Paint.Join.ROUND);
            paint.setColor(color);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float w = getWidth();
            float h = getHeight();
            paint.setStrokeWidth(Math.max(2f, w * 0.12f));
            Path path = new Path();
            path.moveTo(w * 0.62f, h * 0.22f);
            path.lineTo(w * 0.34f, h * 0.5f);
            path.lineTo(w * 0.62f, h * 0.78f);
            canvas.drawPath(path, paint);
        }
    }

    public static class CloseView extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

        public CloseView(Context context, Theme theme) {
            super(context);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeCap(Paint.Cap.ROUND);
            paint.setColor(theme.muted);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float w = getWidth();
            float h = getHeight();
            paint.setStrokeWidth(Math.max(2f, w * 0.08f));
            float a = w * 0.32f;
            float b = w * 0.68f;
            canvas.drawLine(a, h * 0.32f, b, h * 0.68f, paint);
            canvas.drawLine(b, h * 0.32f, a, h * 0.68f, paint);
        }
    }

    public static void ellipsize(TextView view) {
        view.setSingleLine(true);
        view.setEllipsize(TextUtils.TruncateAt.END);
    }

    public static int gravityCenter() {
        return Gravity.CENTER_VERTICAL;
    }
}
