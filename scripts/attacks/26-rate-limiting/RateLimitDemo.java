// Self-contained Rate Limiting deep-dive (CWE-770). JDK-only, logical clock (no sleeps).
// Reimplemented from OWASP API4 / rate-limit bypass research (see DEEP-DIVE.md). Run: java RateLimitDemo
import java.util.*;

public class RateLimitDemo {
    static final int MAX = 5;            // allowed per window
    static final long WINDOW = 60_000;   // 60s

    public static void main(String[] args) {
        // VARIANT 1: no limit at all
        System.out.println("[VARIANT] 1) Sem limite  (OTP 4 digitos = 10.000 tentativas)");
        int processed = 0; for (int i = 0; i < 8; i++) processed++;   // all processed
        System.out.println("[VULNERAVEL] 8 tentativas, bloqueadas=0  (forca bruta livre)");
        System.out.println("[DEFENDIDO] limitar por cliente confiavel -> 429 apos " + MAX);

        // VARIANT 2: per-IP limiter keyed on a SPOOFABLE header (X-Forwarded-For)
        System.out.println("[VARIANT] 2) Bypass por X-Forwarded-For  (chave spoofavel)");
        Map<String,Integer> byXff = new HashMap<>();
        int blockedXff = 0;
        for (int i = 0; i < 20; i++) {                                // attacker rotates XFF each request
            String xff = "10.0.0." + i;                              // BUG: key on attacker-controlled header
            if (byXff.merge(xff, 1, Integer::sum) > MAX) blockedXff++;
        }
        System.out.println("[VULNERAVEL] chave=X-Forwarded-For, 20 tentativas -> bloqueadas=" + blockedXff + "  (rotacionar XFF zera o contador)");
        Map<String,Integer> byRealIp = new HashMap<>(); int blockedReal = 0;
        for (int i = 0; i < 20; i++) if (byRealIp.merge("203.0.113.9", 1, Integer::sum) > MAX) blockedReal++; // real conn IP
        System.out.println("[DEFENDIDO] chave=IP real da conexao -> bloqueadas=" + blockedReal + "  (nao spoofavel)");

        // VARIANT 3: fixed-window boundary burst vs sliding window
        System.out.println("[VARIANT] 3) Janela fixa (burst na virada) vs deslizante");
        // Fixed window: MAX at end of window 1 + MAX at start of window 2 => 2*MAX in a short span.
        int fixedAllowed = fixedWindowAllowed(new long[]{58_000,58_500,59_000,59_500,59_900, 60_100,60_500,61_000,61_500,61_900});
        System.out.println("[VULNERAVEL] janela fixa deixou passar " + fixedAllowed + " em ~4s (2x o limite na virada)");
        int slidingAllowed = slidingWindowAllowed(new long[]{58_000,58_500,59_000,59_500,59_900, 60_100,60_500,61_000,61_500,61_900});
        System.out.println("[DEFENDIDO] janela deslizante deixou passar " + slidingAllowed + " (respeita " + MAX + "/janela)");

        // VARIANT 4: token bucket (smooth) + 429 Retry-After
        System.out.println("[VARIANT] 4) Token bucket + 429 Retry-After");
        System.out.println("[DEFENDIDO] balde de " + MAX + " fichas, recarrega no tempo; excedeu -> 429 + Retry-After");
    }

    // Fixed window: counter resets at each WINDOW boundary (the classic burst bug).
    static int fixedWindowAllowed(long[] ts) {
        int allowed = 0; long windowStart = -1; int count = 0;
        for (long t : ts) {
            long w = t / WINDOW;
            if (w != windowStart) { windowStart = w; count = 0; }
            if (++count <= MAX) allowed++;
        }
        return allowed;
    }
    // Sliding window: count requests within the last WINDOW ms.
    static int slidingWindowAllowed(long[] ts) {
        Deque<Long> q = new ArrayDeque<>(); int allowed = 0;
        for (long t : ts) {
            while (!q.isEmpty() && q.peekFirst() <= t - WINDOW) q.pollFirst();
            if (q.size() < MAX) { q.addLast(t); allowed++; }
        }
        return allowed;
    }
}
