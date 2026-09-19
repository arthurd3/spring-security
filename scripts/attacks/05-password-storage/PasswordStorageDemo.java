// Self-contained Password Storage deep-dive (CWE-256/916). Uses BCrypt (classpath) + JDK MessageDigest.
// Reimplemented from OWASP Password Storage Cheat Sheet (see DEEP-DIVE.md).
// Run: java -cp "$(cat scripts/lib/classpath.txt)" PasswordStorageDemo.java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

public class PasswordStorageDemo {
    static String hex(byte[] b) { return HexFormat.of().formatHex(b); }
    static String digest(String alg, String s) throws Exception {
        return hex(MessageDigest.getInstance(alg).digest(s.getBytes("UTF-8")));
    }

    public static void main(String[] args) throws Exception {
        String pw = "hunter2";

        // VARIANT 1: plaintext - a DB leak hands over the password directly
        System.out.println("[VARIANT] 1) Texto puro");
        System.out.println("[VULNERAVEL] armazenado -> \"" + pw + "\"  (vazou = senha entregue)");
        System.out.println("[DEFENDIDO] nunca armazenar a senha em si (use hash lento com sal)");

        // VARIANT 2: unsalted MD5/SHA-256 - reuse visible + precomputed (rainbow) cracking
        System.out.println("[VARIANT] 2) Hash sem sal (MD5/SHA-256)");
        String md5a = digest("MD5", pw), md5b = digest("MD5", pw);
        Map<String,String> rainbow = Map.of(digest("MD5","hunter2"),"hunter2", digest("MD5","123456"),"123456");
        System.out.println("[VULNERAVEL] MD5 igual p/ senha igual? " + md5a.equals(md5b) + " (reuso visivel); "
                + "quebrado por rainbow table -> " + rainbow.get(md5a));
        System.out.println("[VULNERAVEL] SHA-256 sem sal tambem e rapido de quebrar em GPU: " + digest("SHA-256", pw).substring(0,16) + "...");
        System.out.println("[DEFENDIDO] hash rapido (mesmo com sal) e fraco p/ senha: use bcrypt/argon2/scrypt/pbkdf2");

        // VARIANT 3: salted SHA-256 - hides reuse, but still fast (billions/s on GPU)
        System.out.println("[VARIANT] 3) SHA-256 COM sal");
        byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
        String s1 = digest("SHA-256", hex(salt) + pw);
        byte[] salt2 = new byte[16]; new SecureRandom().nextBytes(salt2);
        String s2 = digest("SHA-256", hex(salt2) + pw);
        System.out.println("[VULNERAVEL] sal esconde reuso (hashes diferentes: " + !s1.equals(s2) + "), MAS SHA e rapido -> ainda quebravel em GPU");
        System.out.println("[DEFENDIDO] preferir funcao LENTA e com custo ajustavel (bcrypt/argon2)");

        // VARIANT 4: bcrypt - salted, slow, tunable (the right answer)
        System.out.println("[VARIANT] 4) BCrypt (correto)");
        BCryptPasswordEncoder enc = new BCryptPasswordEncoder();
        String h1 = enc.encode(pw), h2 = enc.encode(pw);
        System.out.println("[DEFENDIDO] hash -> " + h1);
        System.out.println("[DEFENDIDO] verify(hunter2)=" + enc.matches(pw, h1) + " verify(wrong)=" + enc.matches("wrong", h1)
                + " ; 2 encodes diferentes? " + !h1.equals(h2) + " (sal unico)");

        // VARIANT 5: pepper + upgrade-on-login (concept, printed)
        System.out.println("[VARIANT] 5) Pepper + upgrade-on-login");
        System.out.println("[DEFENDIDO] pepper = segredo do app (fora do DB) misturado antes do hash; "
                + "upgrade-on-login = re-hashear com custo maior quando o usuario loga");
    }
}
