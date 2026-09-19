// Self-contained Brute Force deep-dive (CWE-307). JDK-only. One runnable example PER technique.
// Reimplemented from OWASP Authentication guidance (see DEEP-DIVE.md). Run: java BruteForceDemo
import java.util.*;

public class BruteForceDemo {
    // Directory: user -> password
    static final Map<String, String> USERS = Map.of(
        "arthur","correct-horse", "bob","Winter2025!", "carol","P@ssw0rd", "dave","hunter2", "erin","Password1!");
    // A tiny "known-breached passwords" list (like HaveIBeenPwned - see concepts/hibp-k-anonymity).
    static final Set<String> BREACHED = Set.of("P@ssw0rd","hunter2","123456","password","Password1!","Winter2025!");
    // Real-world "most common passwords 2025" style wordlist (illustrative).
    static final List<String> COMMON_2025 = List.of("123456","Winter2025!","P@ssw0rd","admin","Password1!","qwerty");

    static boolean check(String u, String p) { return USERS.getOrDefault(u, "\0").equals(p); }

    public static void main(String[] args) {
        // VARIANT 1: vertical brute force - one user, many passwords, no lockout
        // real-world: any login without throttling; tools: hydra, medusa
        System.out.println("[VARIANT] 1) Brute force vertical  (1 usuario, N senhas, sem lockout)");
        int tries=0; boolean cracked=false;
        for (String g : List.of("admin","123","letmein","correct-horse")) { tries++; if (check("arthur", g)) { cracked=true; break; } }
        System.out.println("[VULNERAVEL] " + tries + " tentativas processadas, senha quebrada? " + cracked + "  (nada trava)");
        Map<String,Integer> fails=new HashMap<>(); int lockTries=0; boolean locked=false;
        for (String g : List.of("admin","123","letmein","correct-horse")) {
            if (fails.getOrDefault("arthur",0)>=3){locked=true;break;} lockTries++; if(!check("arthur",g)) fails.merge("arthur",1,Integer::sum); }
        System.out.println("[DEFENDIDO] lockout apos 3 -> travou na tentativa " + lockTries + "? " + locked);

        // VARIANT 2: password spraying - one common password, many users (beats per-account lockout)
        // real-world: MS/Okta report spraying as a top initial-access technique
        System.out.println("[VARIANT] 2) Password spraying  (1 senha comum, N usuarios, 1x cada)");
        List<String> hit=new ArrayList<>(); for (String u:USERS.keySet()) if (check(u,"Winter2025!")) hit.add(u);
        System.out.println("[VULNERAVEL] senha 'Winter2025!' abriu: " + hit + "  (1x por conta NAO dispara lockout por conta)");
        System.out.println("[DEFENDIDO] precisa de limite GLOBAL/por-IP + deteccao de spraying + MFA (ver #26 e concepts/totp-mfa)");

        // VARIANT 3: credential stuffing - reuse leaked user:pass pairs
        // real-world: Collections #1-5; Akamai reports bilhoes/ano
        System.out.println("[VARIANT] 3) Credential stuffing  (pares user:senha vazados)");
        System.out.println("[VULNERAVEL] par vazado (carol:P@ssw0rd) funciona? " + check("carol","P@ssw0rd"));
        System.out.println("[DEFENDIDO] bloquear senhas vazadas (HIBP) -> 'P@ssw0rd' vazada? " + BREACHED.contains("P@ssw0rd")
                + " + MFA (ver concepts/hibp-k-anonymity e concepts/totp-mfa)");

        // VARIANT 4: reverse brute force - fix ONE password, iterate the userlist to find who uses it
        System.out.println("[VARIANT] 4) Reverse brute force  (1 senha fixa, itera usuarios)");
        String fixed="hunter2"; List<String> owners=new ArrayList<>();
        for (String u:List.of("arthur","bob","carol","dave","erin","frank")) if (check(u,fixed)) owners.add(u);
        System.out.println("[VULNERAVEL] senha fixa '" + fixed + "' pertence a: " + owners + "  (enumera contas que a usam)");
        System.out.println("[DEFENDIDO] mesma defesa do spraying: limite global/IP + deteccao + MFA (lockout por conta nao pega)");

        // VARIANT 5: most-common-passwords-2025 wordlist spray
        System.out.println("[VARIANT] 5) Wordlist de senhas comuns 2025  (spray com lista real)");
        Set<String> opened=new HashSet<>();
        for (String pw:COMMON_2025) for (String u:USERS.keySet()) if (check(u,pw)) opened.add(u+":"+pw);
        System.out.println("[VULNERAVEL] contas abertas pela wordlist: " + opened + "  (senhas 'fortes-na-aparencia' ainda sao comuns)");
        long stillCommon = COMMON_2025.stream().filter(BREACHED::contains).count();
        System.out.println("[DEFENDIDO] " + stillCommon + "/" + COMMON_2025.size() + " da wordlist estao em listas de vazadas -> politica + HIBP + MFA barram");
    }
}
