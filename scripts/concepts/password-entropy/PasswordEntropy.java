// Concept demo: password entropy and crack-time - why length + a slow hash matter. JDK-only.
// entropy(bits) = length * log2(poolSize); avg guesses = 2^(bits-1). time = guesses / rate. Run: java PasswordEntropy
public class PasswordEntropy {
    static int pool(String p) {
        int size = 0; boolean lo=false,up=false,dig=false,sym=false;
        for (char c : p.toCharArray()) {
            if (c>='a'&&c<='z') lo=true; else if (c>='A'&&c<='Z') up=true;
            else if (c>='0'&&c<='9') dig=true; else sym=true;
        }
        if (lo) size+=26; if (up) size+=26; if (dig) size+=10; if (sym) size+=33; return Math.max(size,1);
    }
    static double bits(String p) { return p.length() * (Math.log(pool(p)) / Math.log(2)); }
    static String crackTime(double bits, double ratePerSec) {
        double secs = Math.pow(2, bits - 1) / ratePerSec;
        double[] u = {60, 3600, 86400, 31536000, 31536000d*1000};
        String[] n = {"segundos","minutos","horas","dias","anos","milenios"};
        int i = 0; double v = secs; while (i < u.length && v >= u[i]) { v = secs / u[i]; i++; }
        return String.format("%.2g %s", (i==0?secs:v), n[i]);
    }
    static void show(String p) {
        double b = bits(p);
        System.out.printf("  '%s'  pool=%d  len=%d  ~%.0f bits%n", p, pool(p), p.length(), b);
        System.out.printf("      MD5/SHA rapido (~1e10/s): %s   |   bcrypt (~1e4/s): %s%n",
                crackTime(b, 1e10), crackTime(b, 1e4));
    }
    public static void main(String[] args) {
        System.out.println("[VULNERAVEL] senhas fracas / hash rapido:");
        show("hunter2"); show("P@ssw0rd"); show("Winter2025!");
        System.out.println("[DEFENDIDO] senha longa (passphrase) + hash lento:");
        show("correct horse battery staple");
        show("9x!Kq2$Lp7#Zt4@Rw1&");
        System.out.println("[INFO] length domina a entropia; e um hash LENTO (bcrypt/argon2, #05) multiplica o tempo de quebra");
        System.out.println("[INFO] NIST SP 800-63B: priorize comprimento, permita passphrases, cheque contra vazadas (concepts/hibp-k-anonymity)");
    }
}
