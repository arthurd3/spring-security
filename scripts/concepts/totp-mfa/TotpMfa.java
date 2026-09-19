// Concept demo: TOTP two-factor auth (RFC 6238, built on HOTP RFC 4226). Pure JDK (HMAC-SHA1).
// Shows why MFA defeats stolen/breached passwords (credential stuffing, spraying). Run: java TotpMfa
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TotpMfa {
    static final byte[] SECRET = "12345678901234567890".getBytes(); // shared secret (base32 in real apps)
    static final int STEP = 30, DIGITS = 6;

    // HOTP (RFC 4226): HMAC-SHA1(secret, counter) -> dynamic truncation -> DIGITS-digit code.
    static String hotp(long counter) throws Exception {
        byte[] msg = new byte[8]; for (int i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xff); counter >>= 8; }
        Mac mac = Mac.getInstance("HmacSHA1"); mac.init(new SecretKeySpec(SECRET, "HmacSHA1"));
        byte[] h = mac.doFinal(msg);
        int off = h[h.length - 1] & 0x0f;
        int bin = ((h[off] & 0x7f) << 24) | ((h[off+1] & 0xff) << 16) | ((h[off+2] & 0xff) << 8) | (h[off+3] & 0xff);
        return String.format("%0" + DIGITS + "d", bin % (int)Math.pow(10, DIGITS));
    }
    static String totp(long timeSec) throws Exception { return hotp(timeSec / STEP); }
    // Validate with a +/- window to tolerate clock drift.
    static boolean validate(String code, long timeSec, int window) throws Exception {
        for (int w = -window; w <= window; w++) if (hotp(timeSec / STEP + w).equals(code)) return true;
        return false;
    }

    public static void main(String[] args) throws Exception {
        long now = 1700000000L;                 // fixed "now" for a deterministic demo
        String valid = totp(now);
        System.out.println("[INFO] codigo TOTP atual (janela de 30s): " + valid);

        // Attacker has the correct PASSWORD (stolen/breached) but not the phone/secret.
        boolean passwordOk = true;              // suppose the password check passed
        System.out.println("[VULNERAVEL] so senha (sem 2FA): atacante com senha vazada entra -> " + passwordOk);

        System.out.println("[DEFENDIDO] senha correta + codigo ERRADO ('000000') -> " + (passwordOk && validate("000000", now, 1)));
        System.out.println("[DEFENDIDO] senha correta + codigo CORRETO -> " + (passwordOk && validate(valid, now, 1)));
        String prev = totp(now - STEP);
        System.out.println("[DEFENDIDO] tolerancia de drift: codigo da janela anterior ainda aceito -> " + validate(prev, now, 1));
        System.out.println("[INFO] MFA neutraliza credential stuffing/spraying (#04): a senha sozinha nao basta");
    }
}
