// Concept demo: why secret comparisons must be constant-time (timing side-channel). JDK-only.
// Naive equals returns early on the first mismatch -> time grows with the matching prefix, leaking it.
// MessageDigest.isEqual compares in constant time. Run: java ConstantTimeCompare
import java.security.MessageDigest;

public class ConstantTimeCompare {
    static boolean naiveEquals(byte[] a, byte[] b) {           // BUG: early return leaks timing
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
    }
    static long timeNaive(byte[] secret, byte[] guess, int iters) {
        long t0 = System.nanoTime(); for (int i = 0; i < iters; i++) naiveEquals(secret, guess); return System.nanoTime() - t0;
    }
    static long timeConst(byte[] secret, byte[] guess, int iters) {
        long t0 = System.nanoTime(); for (int i = 0; i < iters; i++) MessageDigest.isEqual(secret, guess); return System.nanoTime() - t0;
    }
    static byte[] guessMatching(byte[] secret, int matchPrefix) {
        byte[] g = secret.clone(); for (int i = matchPrefix; i < g.length; i++) g[i] = '.'; return g;
    }
    public static void main(String[] args) {
        byte[] secret = "S3cr3tApiToken-0123456789ABCDEF".getBytes();
        int iters = 2_000_000;
        for (int i = 0; i < 3; i++) { timeNaive(secret, secret, iters); timeConst(secret, secret, iters); } // warmup
        long nMatch0  = timeNaive(secret, guessMatching(secret, 0),  iters);
        long nMatchAll= timeNaive(secret, guessMatching(secret, secret.length-1), iters);
        long cMatch0  = timeConst(secret, guessMatching(secret, 0),  iters);
        long cMatchAll= timeConst(secret, guessMatching(secret, secret.length-1), iters);
        System.out.printf("[VULNERAVEL] naiveEquals: prefixo 0 casa=%dms  vs  quase-todo casa=%dms  (tempo cresce -> vaza o segredo)%n",
                nMatch0/1_000_000, nMatchAll/1_000_000);
        System.out.printf("[DEFENDIDO] MessageDigest.isEqual: prefixo 0=%dms  vs  quase-todo=%dms  (praticamente igual -> sem vazamento)%n",
                cMatch0/1_000_000, cMatchAll/1_000_000);
        System.out.println("[INFO] use comparacao em tempo constante p/ tokens/HMAC/senhas (liga a #14 enumeracao por timing e #06 jwt)");
    }
}
