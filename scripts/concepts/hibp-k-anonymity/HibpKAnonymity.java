// Concept demo: check a password against a breach corpus WITHOUT leaking it (k-anonymity).
// This is how "Have I Been Pwned - Pwned Passwords" works. JDK-only, offline (local sample corpus).
// Real API: send only the first 5 hex chars of SHA-1; the server returns all suffixes+counts for that
// prefix; you match the suffix locally. The server never learns your full hash. Run: java HibpKAnonymity
import java.security.MessageDigest;
import java.util.*;

public class HibpKAnonymity {
    static String sha1Upper(String s) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-1").digest(s.getBytes("UTF-8"));
        StringBuilder b = new StringBuilder(); for (byte x : d) b.append(String.format("%02X", x)); return b.toString();
    }

    // A tiny local "Pwned Passwords" corpus: password -> times seen in breaches.
    static final Map<String,Integer> BREACH_CORPUS = Map.of(
        "123456", 37359195, "password", 9545824, "P@ssw0rd", 176050, "Winter2025!", 4120, "qwerty", 3912816);

    // Simulates the API: given a 5-char prefix, return {suffix -> count} for every corpus entry sharing it.
    static Map<String,Integer> rangeQuery(String prefix5) throws Exception {
        Map<String,Integer> out = new LinkedHashMap<>();
        for (var e : BREACH_CORPUS.entrySet()) {
            String h = sha1Upper(e.getKey());
            if (h.startsWith(prefix5)) out.put(h.substring(5), e.getValue()); // only suffix + count leave
        }
        return out;
    }

    // Client-side check: reveals only the prefix; matches the suffix locally.
    static int timesPwned(String password) throws Exception {
        String hash = sha1Upper(password);
        String prefix = hash.substring(0,5), suffix = hash.substring(5);
        Map<String,Integer> range = rangeQuery(prefix); // in reality: HTTPS GET .../range/<prefix>
        return range.getOrDefault(suffix, 0);
    }

    public static void main(String[] args) throws Exception {
        String weak = "P@ssw0rd";
        String hash = sha1Upper(weak);
        System.out.println("[INFO] senha: " + weak + " | SHA-1: " + hash);
        System.out.println("[INFO] k-anonymity: so o PREFIXO '" + hash.substring(0,5) + "' e enviado; o sufixo (" +
                hash.substring(5,15) + "...) e comparado localmente -> a senha nunca vaza");
        System.out.println("[VULNERAVEL] permitir '" + weak + "' no cadastro -> vista " + timesPwned(weak) + " vezes em vazamentos");
        String strong = "9x!Kq2$" + Long.toHexString(0xC0FFEE1234L); // um exemplo forte/aleatorio
        System.out.println("[DEFENDIDO] bloquear senhas vazadas: '" + weak + "' pwned=" + (timesPwned(weak)>0)
                + " -> REJEITADO ; senha forte pwned=" + (timesPwned(strong)>0) + " -> aceita");
    }
}
