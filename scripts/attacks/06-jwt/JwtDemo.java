// Self-contained JWT deep-dive (CWE-345/347). Pure JDK crypto (HMAC + RSA). No libraries.
// Variants: alg=none, weak secret (dictionary), missing exp, RS256->HS256 algorithm confusion.
// Reimplemented from PortSwigger JWT / OWASP (see DEEP-DIVE.md). Run: java JwtDemo
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class JwtDemo {
    static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    static byte[] ub64(String s) { return Base64.getUrlDecoder().decode(s); }
    static String bs(String s) { return b64(s.getBytes(StandardCharsets.UTF_8)); }
    static String payloadOf(String t) { return new String(ub64(t.split("\\.")[1]), StandardCharsets.UTF_8); }

    static String hmac(String data, byte[] key) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(key, "HmacSHA256"));
        return b64(m.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    public static void main(String[] args) throws Exception {
        // ---- VARIANT 1: alg=none ----
        System.out.println("[VARIANT] 1) alg=none  (token sem assinatura)");
        String forged = bs("{\"alg\":\"none\"}") + "." + bs("{\"sub\":\"attacker\",\"roles\":[\"ADMIN\"]}") + ".";
        System.out.println("[VULNERAVEL] parser ingenuo confia -> " + payloadOf(forged));
        System.out.println("[DEFENDIDO] verify exige assinatura HS256 valida -> aceito? " + verifyHmac(forged, "strong-secret-32-bytes-minimum!!".getBytes()));

        // ---- VARIANT 2: weak secret cracked by dictionary ----
        System.out.println("[VARIANT] 2) Segredo fraco  (quebrado por dicionario)");
        String weak = "secret";
        String h = bs("{\"alg\":\"HS256\"}"), p = bs("{\"sub\":\"admin\"}");
        String tok = h + "." + p + "." + hmac(h + "." + p, weak.getBytes());
        String cracked = null;
        for (String cand : new String[]{"123456","password","secret","changeit"})
            if (hmac(h + "." + p, cand.getBytes()).equals(tok.split("\\.")[2])) { cracked = cand; break; }
        System.out.println("[VULNERAVEL] segredo recuperado por wordlist -> '" + cracked + "' (agora forja qualquer token)");
        System.out.println("[DEFENDIDO] segredo forte de 256+ bits nao esta em wordlist -> inviavel");

        // ---- VARIANT 3: missing exp check ----
        System.out.println("[VARIANT] 3) Sem checar expiracao (exp)");
        byte[] key = "strong-secret-32-bytes-minimum!!".getBytes();
        String hp = bs("{\"alg\":\"HS256\"}"), pp = bs("{\"sub\":\"arthur\",\"exp\":1000000000}"); // exp no passado (2001)
        String expired = hp + "." + pp + "." + hmac(hp + "." + pp, key);
        System.out.println("[VULNERAVEL] so confere assinatura (ignora exp) -> aceito? " + verifyHmac(expired, key));
        System.out.println("[DEFENDIDO] confere assinatura E exp -> aceito? " + verifyHmacAndExp(expired, key) + " (expirado)");

        // ---- VARIANT 4: RS256 -> HS256 algorithm confusion ----
        System.out.println("[VARIANT] 4) Confusao de algoritmo  (RS256 -> HS256 com a chave publica)");
        KeyPair kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
        byte[] pub = kp.getPublic().getEncoded(); // public -> attacker knows it
        // Attacker forges an HS256 token using the PUBLIC key bytes as the HMAC secret:
        String fh = bs("{\"alg\":\"HS256\"}"), fp = bs("{\"sub\":\"attacker\",\"roles\":[\"ADMIN\"]}");
        String confused = fh + "." + fp + "." + hmac(fh + "." + fp, pub);
        System.out.println("[VULNERAVEL] verificador escolhe o alg do header e usa a chave publica como segredo HMAC -> aceito? "
                + vulnVerifyByHeaderAlg(confused, kp.getPublic(), pub));
        System.out.println("[DEFENDIDO] verificador FIXA o algoritmo esperado (RS256) -> aceito? "
                + safeVerifyPinnedRs256(confused, kp.getPublic()));
    }

    // Safe HMAC verify: requires HS256 header + matching signature.
    static boolean verifyHmac(String t, byte[] key) throws Exception {
        String[] a = t.split("\\.", -1);
        if (a.length < 3 || a[2].isEmpty()) return false;
        if (!new String(ub64(a[0])).contains("HS256")) return false;
        return hmac(a[0] + "." + a[1], key).equals(a[2]);
    }
    static boolean verifyHmacAndExp(String t, byte[] key) throws Exception {
        if (!verifyHmac(t, key)) return false;
        String pl = payloadOf(t); long now = 1893456000L; // fixed "now" (2030) for determinism
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"exp\":(\\d+)").matcher(pl);
        return !(m.find() && Long.parseLong(m.group(1)) < now);
    }
    // Vulnerable: picks the algorithm from the token header (confusable).
    static boolean vulnVerifyByHeaderAlg(String t, PublicKey rsaPub, byte[] pubBytes) throws Exception {
        String[] a = t.split("\\.", -1); String alg = new String(ub64(a[0]));
        if (alg.contains("HS256")) return hmac(a[0] + "." + a[1], pubBytes).equals(a[2]); // BUG: pub key as HMAC secret
        return false; // (RS256 path omitted for brevity)
    }
    // Safe: algorithm is pinned to RS256; an HS256 token is rejected outright.
    static boolean safeVerifyPinnedRs256(String t, PublicKey rsaPub) throws Exception {
        String[] a = t.split("\\.", -1);
        if (!new String(ub64(a[0])).contains("RS256")) return false; // pin the alg
        Signature s = Signature.getInstance("SHA256withRSA"); s.initVerify(rsaPub);
        s.update((a[0] + "." + a[1]).getBytes(StandardCharsets.UTF_8));
        return s.verify(ub64(a[2]));
    }
}
