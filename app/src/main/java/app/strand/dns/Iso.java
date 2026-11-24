package app.strand.dns;

import java.util.Calendar;
import java.util.TimeZone;

/** ISO-8601 timestamps without java.time, so API 24 is enough. */
public final class Iso {
    private Iso() {}

    public static String now() {
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        return String.format(
                "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                c.get(Calendar.YEAR),
                c.get(Calendar.MONTH) + 1,
                c.get(Calendar.DAY_OF_MONTH),
                c.get(Calendar.HOUR_OF_DAY),
                c.get(Calendar.MINUTE),
                c.get(Calendar.SECOND),
                c.get(Calendar.MILLISECOND));
    }
}
