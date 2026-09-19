// Self-contained Insecure Randomness deep-dive (CWE-330). JDK-only.
// Reimplemented from OWASP guidance (see DEEP-DIVE.md). Run: java RandomnessDemo
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Random;
import java.util.UUID;

public class RandomnessDemo {
    static final SecureRandom SECURE = new SecureRandom();

    public static void main(String[] args) {
        // VARIANT 1: same seed -> same sequence
        System.out.println("[VARIANT] 1) Semente conhecida -> saida reproduzivel");
        System.out.println("[VULNERAVEL] new Random(42).nextLong() 2x -> "
                + Long.toHexString(new Random(42).nextLong()) + " == " + Long.toHexString(new Random(42).nextLong()));
        System.out.println("[DEFENDIDO] SecureRandom nao aceita semente do atacante e nao repete");

        // VARIANT 2: time-seeded token -> brute force the seed and PREDICT the next token
        System.out.println("[VARIANT] 2) Token semeado pelo tempo -> quebra a semente e preve o proximo");
        long serverSecond = 1737045123L;                 // server seeded with the current epoch second
        long issued = new Random(serverSecond).nextLong(); // token dado ao usuario
        long recovered = 0;
        for (long s = serverSecond - 5000; s <= serverSecond + 5000; s++)   // attacker knows approx time
            if (new Random(s).nextLong() == issued) { recovered = s; break; }
        long predicted = new Random(recovered).nextLong(); // reproduce -> predict future tokens
        System.out.println("[VULNERAVEL] token observado=" + Long.toHexString(issued)
                + " ; semente recuperada=" + recovered + " ; proximo token previsto=" + Long.toHexString(predicted));
        System.out.println("[DEFENDIDO] SecureRandom(256 bits): sem semente adivinhavel, sem previsao");

        // VARIANT 3: predictable UUID/token (java.util.Random) vs SecureRandom
        System.out.println("[VARIANT] 3) UUID/token previsivel");
        Random r = new Random(serverSecond);
        UUID weak = new UUID(r.nextLong(), r.nextLong());   // UUID a partir de PRNG semeado
        System.out.println("[VULNERAVEL] UUID de java.util.Random (semente do tempo) -> reproduzivel: " + weak);
        System.out.println("[DEFENDIDO] UUID.randomUUID() usa SecureRandom -> " + UUID.randomUUID());

        // VARIANT 4: entropy/length
        System.out.println("[VARIANT] 4) Entropia/comprimento do token");
        System.out.println("[VULNERAVEL] token de 4 digitos (10^4) ou nextInt(1000000): forca bruta trivial");
        byte[] b = new byte[32]; SECURE.nextBytes(b);
        System.out.println("[DEFENDIDO] 256 bits: " + HexFormat.of().formatHex(b));
    }
}
