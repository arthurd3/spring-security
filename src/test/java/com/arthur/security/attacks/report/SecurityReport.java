package com.arthur.security.attacks.report;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Prints each demonstrated attack to the terminal, plus a grouped summary table at the end of the run.
 *
 * <p>Tests call {@link #vulnerable} right after asserting that an attack succeeded against the
 * deliberately-insecure example code, and {@link #defended} after asserting that the same attack is
 * blocked by the real application. Each call prints one line immediately, so the output reads in test
 * order, and every entry is also accumulated for the summary table.
 *
 * <p>The table is emitted by {@link SecurityReportListener} when the JUnit test plan finishes, which
 * is early enough for Surefire to capture the output. A JVM shutdown hook is kept as a fallback for
 * IDE runs; {@link #printSummary()} is idempotent so the two can never both print.
 */
public final class SecurityReport {

    /** One demonstrated scenario: either an attack that worked, or an attack that was blocked. */
    private record Entry(String category, boolean blocked, String attack, String observed) {
    }

    private static final List<Entry> ENTRIES = new ArrayList<>();
    private static boolean printed;

    /** Honours the NO_COLOR convention so piped/CI output stays plain. */
    private static final boolean COLOR = System.getenv("NO_COLOR") == null;

    private static final String ESC = String.valueOf((char) 27);
    private static final String RESET = ansi("0m");
    private static final String RED = ansi("31m");
    private static final String GREEN = ansi("32m");
    private static final String CYAN = ansi("36m");
    private static final String DIM = ansi("2m");
    private static final String BOLD = ansi("1m");

    static {
        // Fallback only. SecurityReportListener normally prints first; a shutdown hook runs too late
        // for Surefire to capture its output, but still helps when tests are run straight from an IDE.
        Runtime.getRuntime().addShutdownHook(new Thread(SecurityReport::printSummary, "security-report"));
    }

    private SecurityReport() {
    }

    /** Records an attack that SUCCEEDED against the intentionally vulnerable example code. */
    public static void vulnerable(String category, String attack, String observed) {
        record(new Entry(category, false, attack, observed));
    }

    /** Records an attack that was BLOCKED by the hardened application. */
    public static void defended(String category, String attack, String observed) {
        record(new Entry(category, true, attack, observed));
    }

    private static synchronized void record(Entry entry) {
        ENTRIES.add(entry);
        String label = entry.blocked()
                ? GREEN + "OK  DEFENDIDO " + RESET
                : RED + "XX  VULNERAVEL" + RESET;
        System.out.printf("  %s %s%-20s%s %-46s %s-> %s%s%n",
                label, CYAN, truncate(entry.category(), 20), RESET,
                truncate(entry.attack(), 46), DIM, entry.observed(), RESET);
    }

    /** Prints the grouped table. Idempotent: only the first caller produces output. */
    static synchronized void printSummary() {
        if (printed || ENTRIES.isEmpty()) {
            return;
        }
        printed = true;

        Map<String, int[]> byCategory = new LinkedHashMap<>();
        for (Entry entry : ENTRIES) {
            int[] counts = byCategory.computeIfAbsent(entry.category(), key -> new int[2]);
            counts[entry.blocked() ? 1 : 0]++;
        }

        String rule = "=".repeat(72);
        StringBuilder out = new StringBuilder();
        out.append(System.lineSeparator()).append(BOLD).append(rule).append(RESET).append(System.lineSeparator());
        out.append(BOLD).append("  RELATORIO DE SEGURANCA  -  ataques demonstrados vs. defesas")
                .append(RESET).append(System.lineSeparator());
        out.append(BOLD).append(rule).append(RESET).append(System.lineSeparator());
        out.append(String.format("  %-32s %14s %14s%n", "CATEGORIA", "VULNERAVEL", "DEFENDIDO"));
        out.append("  ").append("-".repeat(68)).append(System.lineSeparator());

        int totalVulnerable = 0;
        int totalDefended = 0;
        for (Map.Entry<String, int[]> row : byCategory.entrySet()) {
            int vulnerable = row.getValue()[0];
            int defended = row.getValue()[1];
            totalVulnerable += vulnerable;
            totalDefended += defended;
            out.append(String.format("  %-32s %s%14d%s %s%14d%s%n",
                    truncate(row.getKey(), 32),
                    vulnerable > 0 ? RED : DIM, vulnerable, RESET,
                    defended > 0 ? GREEN : DIM, defended, RESET));
        }

        out.append("  ").append("-".repeat(68)).append(System.lineSeparator());
        out.append(String.format("  %s%-32s%s %s%14d%s %s%14d%s%n",
                BOLD, "TOTAL (" + byCategory.size() + " categorias)", RESET,
                RED + BOLD, totalVulnerable, RESET,
                GREEN + BOLD, totalDefended, RESET));
        out.append(BOLD).append(rule).append(RESET).append(System.lineSeparator());
        out.append(DIM)
                .append("  VULNERAVEL = ataque comprovadamente bem-sucedido contra o codigo inseguro de")
                .append(System.lineSeparator())
                .append("               exemplo, isolado em src/test, fora do classpath de producao.")
                .append(System.lineSeparator())
                .append("  DEFENDIDO  = o mesmo ataque barrado pela aplicacao real.")
                .append(System.lineSeparator())
                .append(RESET);

        System.out.print(out);
        System.out.flush();
    }

    private static String ansi(String code) {
        return COLOR ? ESC + "[" + code : "";
    }

    private static String truncate(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max - 3) + "...";
    }
}
