package app.strand.dns;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.util.List;

/** The resolver form, in the compact home card or the full diagnostics card. */
public final class FormView extends LinearLayout {
    public interface Listener {
        void onEndpoint(FormView source, String value);

        void onName(FormView source, String value);

        void onProtocol(String protocol);

        void onQtype(String qtype);

        void onStrict(boolean strict);

        void onPreset(Endpoints.Preset preset);

        void onCheck(FormView source);

        void onCheckBoth(FormView source);
    }

    private final Theme theme;
    private final boolean full;
    private final Listener listener;
    private final EditText resolver;
    private final EditText nameField;
    private final TextView dohButton;
    private final TextView dotButton;
    private final TextView typeButton;
    private final LinearLayout typeMenu;
    private final LinearLayout suggestions;
    private final LinearLayout presets;
    private final TextView errorView;
    private final TextView checkButton;
    private final TextView bothButton;
    private final View strictKnob;
    private final GradientDrawable strictTrack;
    private boolean mute;
    private boolean focused;
    private String qtype = "A";
    private boolean strict = true;

    public FormView(Context context, Theme theme, boolean full, Listener listener) {
        super(context);
        this.theme = theme;
        this.full = full;
        this.listener = listener;
        setOrientation(VERTICAL);

        LinearLayout header = Ui.row(context, Gravity.CENTER_VERTICAL);
        LinearLayout titles = Ui.column(context);
        titles.addView(Ui.eyebrow(context, theme, "STRAND DNS"));
        TextView subtitle = Ui.text(context, theme, "Encrypted DNS", 14, theme.foreground, theme.sans);
        LinearLayout.LayoutParams subLp = Ui.matchTop(theme.dp(4));
        titles.addView(subtitle, subLp);
        LinearLayout.LayoutParams titlesLp = new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f);
        header.addView(titles, titlesLp);

        LinearLayout toggle = Ui.row(context, Gravity.CENTER_VERTICAL);
        toggle.setBackground(theme.rounded(theme.background, 0, 999));
        toggle.setPadding(theme.dp(4), theme.dp(4), theme.dp(4), theme.dp(4));
        dohButton = protocolButton("DoH");
        dotButton = protocolButton("DoT");
        dohButton.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                listener.onProtocol("doh");
            }
        });
        dotButton.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                listener.onProtocol("dot");
            }
        });
        toggle.addView(dohButton);
        toggle.addView(dotButton);
        header.addView(toggle);
        addView(header);

        TextView resolverLabel = Ui.text(context, theme, "Resolver", 12, theme.muted, theme.sans);
        addView(resolverLabel, Ui.matchTop(theme.dp(16)));

        FrameLayout field = new FrameLayout(context);
        field.setBackground(theme.rounded(theme.background, theme.line, 20));
        resolver = field(context, "Search Cloudflare, or paste a host");
        resolver.setPadding(theme.dp(12), 0, theme.dp(48), 0);
        resolver.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            public void afterTextChanged(Editable s) {
                if (mute) return;
                listener.onEndpoint(FormView.this, s.toString());
                renderSuggestions();
            }
        });
        resolver.setOnFocusChangeListener(new OnFocusChangeListener() {
            public void onFocusChange(View v, boolean hasFocus) {
                focused = hasFocus;
                if (!hasFocus) {
                    postDelayed(new Runnable() {
                        public void run() {
                            if (!focused) renderSuggestions();
                        }
                    }, 180);
                } else {
                    renderSuggestions();
                }
            }
        });
        FrameLayout.LayoutParams fieldLp = new FrameLayout.LayoutParams(LayoutParams.MATCH_PARENT, theme.dp(48));
        field.addView(resolver, fieldLp);
        FrameLayout clear = new FrameLayout(context);
        clear.setContentDescription("Clear resolver");
        Ui.CloseView close = new Ui.CloseView(context, theme);
        FrameLayout.LayoutParams closeLp = new FrameLayout.LayoutParams(theme.dp(16), theme.dp(16), Gravity.CENTER);
        clear.addView(close, closeLp);
        clear.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                listener.onEndpoint(FormView.this, "");
                setResolverQuiet("");
                resolver.requestFocus();
            }
        });
        FrameLayout.LayoutParams clearLp = new FrameLayout.LayoutParams(theme.dp(44), theme.dp(48), Gravity.END);
        field.addView(clear, clearLp);
        addView(field, Ui.matchTop(theme.dp(6)));

        suggestions = Ui.column(context);
        suggestions.setBackground(theme.rounded(theme.background, theme.line, 20));
        suggestions.setVisibility(GONE);
        addView(suggestions, Ui.matchTop(theme.dp(8)));

        presets = Ui.column(context);
        addView(presets, Ui.matchTop(theme.dp(8)));

        LinearLayout queryRow = Ui.row(context, Gravity.BOTTOM);
        LinearLayout queryCol = Ui.column(context);
        queryCol.addView(Ui.text(context, theme, "Query", 12, theme.muted, theme.sans));
        nameField = field(context, "example.com");
        nameField.setBackground(theme.rounded(theme.background, theme.line, 20));
        nameField.setPadding(theme.dp(12), 0, theme.dp(12), 0);
        nameField.setImeOptions(EditorInfo.IME_ACTION_DONE);
        nameField.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, android.view.KeyEvent event) {
                if (actionId == EditorInfo.IME_ACTION_DONE) {
                    check();
                    return true;
                }
                return false;
            }
        });
        nameField.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            public void afterTextChanged(Editable s) {
                if (!mute) listener.onName(FormView.this, s.toString());
            }
        });
        LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(LayoutParams.MATCH_PARENT, theme.dp(48));
        nameLp.topMargin = theme.dp(6);
        queryCol.addView(nameField, nameLp);
        queryRow.addView(queryCol, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));

        LinearLayout typeCol = Ui.column(context);
        LinearLayout.LayoutParams typeColLp = new LinearLayout.LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        typeColLp.leftMargin = theme.dp(8);
        TextView typeLabel = Ui.text(context, theme, "Type", 12, theme.muted, theme.sans);
        typeCol.addView(typeLabel);
        typeButton = Ui.text(context, theme, "A", 14, theme.foreground, theme.mono);
        typeButton.setGravity(Gravity.CENTER);
        typeButton.setBackground(theme.rounded(theme.background, theme.line, 20));
        typeButton.setMinimumWidth(theme.dp(84));
        typeButton.setMinimumHeight(theme.dp(48));
        typeButton.setContentDescription("Record type");
        typeButton.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                typeMenu.setVisibility(typeMenu.getVisibility() == VISIBLE ? GONE : VISIBLE);
            }
        });
        LinearLayout.LayoutParams typeBtnLp = new LinearLayout.LayoutParams(LayoutParams.WRAP_CONTENT, theme.dp(48));
        typeBtnLp.topMargin = theme.dp(6);
        typeCol.addView(typeButton, typeBtnLp);
        queryRow.addView(typeCol, typeColLp);
        addView(queryRow, Ui.matchTop(theme.dp(12)));

        typeMenu = Ui.column(context);
        typeMenu.setBackground(theme.rounded(theme.background, theme.line, 20));
        typeMenu.setVisibility(GONE);
        addView(typeMenu, Ui.matchTop(theme.dp(8)));

        if (full) {
            final LinearLayout strictRow = Ui.row(context, Gravity.CENTER_VERTICAL);
            strictRow.setBackground(theme.rounded(theme.background, theme.line, 20));
            strictRow.setPadding(theme.dp(12), 0, theme.dp(8), 0);
            strictRow.setMinimumHeight(theme.dp(48));
            TextView strictLabel = Ui.text(context, theme, "Require a trusted certificate", 14, theme.foreground, theme.sans);
            strictRow.addView(strictLabel, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
            strictTrack = new GradientDrawable();
            strictTrack.setCornerRadius(theme.dp(999));
            FrameLayout track = new FrameLayout(context);
            track.setBackground(strictTrack);
            strictKnob = new View(context);
            GradientDrawable knob = new GradientDrawable();
            knob.setShape(GradientDrawable.OVAL);
            knob.setColor(theme.background);
            strictKnob.setBackground(knob);
            FrameLayout.LayoutParams knobLp = new FrameLayout.LayoutParams(theme.dp(24), theme.dp(24), Gravity.CENTER_VERTICAL);
            knobLp.leftMargin = theme.dp(2);
            track.addView(strictKnob, knobLp);
            LinearLayout.LayoutParams trackLp = new LinearLayout.LayoutParams(theme.dp(48), theme.dp(28));
            strictRow.addView(track, trackLp);
            strictRow.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    listener.onStrict(!strict);
                }
            });
            addView(strictRow, Ui.matchTop(theme.dp(12)));
        } else {
            strictTrack = null;
            strictKnob = null;
        }

        errorView = Ui.text(context, theme, "", 14, theme.fault, theme.sans);
        errorView.setVisibility(GONE);
        addView(errorView, Ui.matchTop(theme.dp(12)));

        checkButton = Ui.text(context, theme, "Check", 14, theme.signalInk, theme.sansSemi);
        checkButton.setGravity(Gravity.CENTER);
        checkButton.setBackground(theme.rounded(theme.signal, 0, 20));
        checkButton.setMinimumHeight(theme.dp(48));
        checkButton.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                check();
            }
        });
        addView(checkButton, Ui.matchTop(theme.dp(16)));

        if (full) {
            bothButton = Ui.text(context, theme, "Check DoH and DoT", 14, theme.foreground, theme.sans);
            bothButton.setGravity(Gravity.CENTER);
            bothButton.setBackground(theme.rounded(0x00000000, theme.line, 20));
            bothButton.setMinimumHeight(theme.dp(48));
            bothButton.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    hideKeyboard();
                    if (resolver.getText().toString().trim().length() == 0) {
                        showError("Choose a resolver, or paste a DoH URL or DoT host.");
                        return;
                    }
                    showError(null);
                    listener.onCheckBoth(FormView.this);
                }
            });
            addView(bothButton, Ui.matchTop(theme.dp(8)));
        } else {
            bothButton = null;
        }
        renderTypeMenu();
        renderSuggestions();
    }

    public void showError(String message) {
        if (message == null || message.length() == 0) {
            errorView.setVisibility(GONE);
            errorView.setText("");
            return;
        }
        errorView.setText(message);
        errorView.setVisibility(VISIBLE);
    }

    public void setBusy(boolean busy, boolean hasResult) {
        checkButton.setEnabled(!busy);
        checkButton.setAlpha(busy ? 0.5f : 1f);
        checkButton.setText(busy ? "Checking the encrypted path" : (hasResult ? "Check again" : "Check"));
        if (bothButton != null) {
            bothButton.setEnabled(!busy);
            bothButton.setAlpha(busy ? 0.5f : 1f);
        }
    }

    public void reflect(Models.Session session) {
        mute = true;
        if (!resolver.getText().toString().equals(session.endpoint)) {
            resolver.setText(session.endpoint);
            resolver.setSelection(session.endpoint.length());
        }
        if (!nameField.getText().toString().equals(session.name)) {
            nameField.setText(session.name);
            nameField.setSelection(session.name.length());
        }
        mute = false;
        qtype = session.qtype;
        strict = session.strict;
        typeButton.setText(qtype);
        paintProtocol(session.protocol);
        paintStrict();
        renderTypeMenu();
        renderSuggestions();
    }

    public void setResolverQuiet(String value) {
        mute = true;
        resolver.setText(value);
        resolver.setSelection(value.length());
        mute = false;
        renderSuggestions();
    }

    public void setNameQuiet(String value) {
        mute = true;
        nameField.setText(value);
        nameField.setSelection(value.length());
        mute = false;
    }

    private void check() {
        hideKeyboard();
        if (resolver.getText().toString().trim().length() == 0) {
            showError("Choose a resolver, or paste a DoH URL or DoT host.");
            return;
        }
        showError(null);
        listener.onCheck(this);
    }

    private void hideKeyboard() {
        InputMethodManager imm = (InputMethodManager) getContext().getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) imm.hideSoftInputFromWindow(getWindowToken(), 0);
        resolver.clearFocus();
        nameField.clearFocus();
    }

    private void paintProtocol(String protocol) {
        boolean doh = !"dot".equals(protocol);
        dohButton.setBackground(theme.rounded(doh ? theme.surfaceAlt : 0x00000000, 0, 999));
        dohButton.setTextColor(doh ? theme.foreground : theme.muted);
        dotButton.setBackground(theme.rounded(doh ? 0x00000000 : theme.surfaceAlt, 0, 999));
        dotButton.setTextColor(doh ? theme.muted : theme.foreground);
    }

    private void paintStrict() {
        if (strictTrack == null || strictKnob == null) return;
        strictTrack.setColor(strict ? theme.signal : theme.line);
        FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) strictKnob.getLayoutParams();
        lp.gravity = Gravity.CENTER_VERTICAL | (strict ? Gravity.END : Gravity.START);
        lp.leftMargin = strict ? 0 : theme.dp(2);
        lp.rightMargin = strict ? theme.dp(2) : 0;
        strictKnob.setLayoutParams(lp);
    }

    private TextView protocolButton(String label) {
        TextView button = Ui.text(getContext(), theme, label, 14, theme.muted, theme.sans);
        button.setGravity(Gravity.CENTER);
        button.setMinimumWidth(theme.dp(56));
        button.setMinimumHeight(theme.dp(40));
        button.setPadding(theme.dp(12), 0, theme.dp(12), 0);
        return button;
    }

    private EditText field(Context context, String hint) {
        EditText edit = new EditText(context);
        edit.setHint(hint);
        edit.setHintTextColor(theme.muted);
        edit.setTextColor(theme.foreground);
        edit.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        edit.setTypeface(theme.sans);
        edit.setSingleLine(true);
        edit.setBackgroundColor(0x00000000);
        edit.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        edit.setImeOptions(EditorInfo.IME_ACTION_NEXT);
        edit.setGravity(Gravity.CENTER_VERTICAL);
        return edit;
    }

    private void renderTypeMenu() {
        typeMenu.removeAllViews();
        String[] types = full
                ? new String[] {"A", "AAAA", "TXT", "NS", "MX", "HTTPS", "CNAME"}
                : new String[] {"A", "AAAA", "TXT"};
        boolean has = false;
        for (int i = 0; i < types.length; i++) if (types[i].equals(qtype)) has = true;
        if (!has) {
            String[] next = new String[types.length + 1];
            System.arraycopy(types, 0, next, 0, types.length);
            next[types.length] = qtype;
            types = next;
        }
        for (int i = 0; i < types.length; i++) {
            final String type = types[i];
            TextView item = Ui.text(getContext(), theme, type, 14, type.equals(qtype) ? theme.foreground : theme.muted, theme.mono);
            item.setGravity(Gravity.CENTER_VERTICAL);
            item.setPadding(theme.dp(12), 0, theme.dp(12), 0);
            item.setMinimumHeight(theme.dp(44));
            item.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    typeMenu.setVisibility(GONE);
                    listener.onQtype(type);
                }
            });
            typeMenu.addView(item, new LayoutParams(LayoutParams.MATCH_PARENT, theme.dp(44)));
        }
    }

    private void renderSuggestions() {
        String text = resolver.getText() == null ? "" : resolver.getText().toString();
        boolean showPresets = !focused && text.trim().length() == 0;
        presets.setVisibility(showPresets ? VISIBLE : GONE);
        if (showPresets && presets.getChildCount() == 0) fillPresets();
        if (!focused) {
            suggestions.setVisibility(GONE);
            return;
        }
        List<Endpoints.Preset> matches = Endpoints.filterPresets(text);
        if (text.trim().length() == 0 && matches.size() > 5) matches = matches.subList(0, 5);
        suggestions.removeAllViews();
        if (matches.size() == 0) {
            suggestions.setVisibility(GONE);
            return;
        }
        suggestions.setVisibility(VISIBLE);
        for (int i = 0; i < matches.size(); i++) {
            final Endpoints.Preset preset = matches.get(i);
            LinearLayout row = Ui.row(getContext(), Gravity.CENTER_VERTICAL);
            row.setPadding(theme.dp(12), 0, theme.dp(12), 0);
            row.setMinimumHeight(theme.dp(44));
            TextView name = Ui.text(getContext(), theme, preset.name, 14, theme.foreground, theme.sans);
            Ui.ellipsize(name);
            row.addView(name, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
            TextView hint = Ui.text(getContext(), theme, preset.hint, 12, theme.muted, theme.mono);
            LinearLayout.LayoutParams hintLp = new LinearLayout.LayoutParams(theme.dp(140), LayoutParams.WRAP_CONTENT);
            hintLp.leftMargin = theme.dp(8);
            hint.setGravity(Gravity.END);
            Ui.ellipsize(hint);
            row.addView(hint, hintLp);
            row.setOnTouchListener(new OnTouchListener() {
                public boolean onTouch(View v, MotionEvent event) {
                    if (event.getAction() == MotionEvent.ACTION_DOWN) {
                        listener.onPreset(preset);
                        focused = false;
                        suggestions.setVisibility(GONE);
                        return true;
                    }
                    return false;
                }
            });
            suggestions.addView(row, new LayoutParams(LayoutParams.MATCH_PARENT, theme.dp(44)));
        }
    }

    private void fillPresets() {
        presets.removeAllViews();
        for (int rowIndex = 0; rowIndex < 2; rowIndex++) {
            LinearLayout row = Ui.row(getContext(), Gravity.CENTER_VERTICAL);
            for (int col = 0; col < 2; col++) {
                final Endpoints.Preset preset = Endpoints.PRESETS[rowIndex * 2 + col];
                TextView button = Ui.text(getContext(), theme, preset.name, 14, theme.foreground, theme.sans);
                button.setGravity(Gravity.CENTER_VERTICAL);
                button.setPadding(theme.dp(12), 0, theme.dp(12), 0);
                button.setBackground(theme.rounded(theme.background, theme.line, 20));
                button.setMinimumHeight(theme.dp(44));
                button.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        listener.onPreset(preset);
                    }
                });
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, theme.dp(44), 1f);
                if (col == 1) lp.leftMargin = theme.dp(8);
                row.addView(button, lp);
            }
            LinearLayout.LayoutParams rowLp = Ui.match();
            if (rowIndex == 1) rowLp.topMargin = theme.dp(8);
            presets.addView(row, rowLp);
        }
    }
}
