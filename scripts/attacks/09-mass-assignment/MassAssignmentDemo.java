// Self-contained Mass Assignment deep-dive (CWE-915). Uses Jackson (classpath).
// Reimplemented from OWASP Mass Assignment / Homakov's GitHub 2012 (see DEEP-DIVE.md).
// Run: java -cp "$(cat scripts/lib/classpath.txt)" MassAssignmentDemo.java
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class MassAssignmentDemo {
    // Over-broad model a careless codebase binds directly (has privileged fields).
    public static class AccountModel {
        public String username, password, role = "USER";
        public boolean admin = false;
        public int balance = 0;
    }
    // Safe input DTO - only what the client may set.
    public record Registration(String username, String password) {}
    // Alternative safe model: explicitly reject unknown fields.
    @JsonIgnoreProperties(ignoreUnknown = false)
    public static class StrictAccount { public String username, password; }

    public static void main(String[] args) throws Exception {
        ObjectMapper om = new ObjectMapper();

        // VARIANT 1: role escalation
        System.out.println("[VARIANT] 1) Escalonar 'role' -> ADMIN");
        String j1 = "{\"username\":\"mallory\",\"password\":\"x\",\"role\":\"ADMIN\"}";
        System.out.println("[VULNERAVEL] bind AccountModel -> role=" + om.readValue(j1, AccountModel.class).role);
        ObjectMapper safe = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        System.out.println("[DEFENDIDO] bind Registration -> role fixado pelo servidor = USER (campo ignorado)");

        // VARIANT 2: isAdmin boolean
        System.out.println("[VARIANT] 2) Flag booleana isAdmin");
        String j2 = "{\"username\":\"mallory\",\"password\":\"x\",\"admin\":true}";
        System.out.println("[VULNERAVEL] bind AccountModel -> admin=" + om.readValue(j2, AccountModel.class).admin);
        System.out.println("[DEFENDIDO] Registration nao tem 'admin' -> nao ha onde encaixar");

        // VARIANT 3: price/balance tampering
        System.out.println("[VARIANT] 3) Adulterar saldo/preco");
        String j3 = "{\"username\":\"mallory\",\"password\":\"x\",\"balance\":1000000}";
        System.out.println("[VULNERAVEL] bind AccountModel -> balance=" + om.readValue(j3, AccountModel.class).balance);
        System.out.println("[DEFENDIDO] balance vem da regra de negocio no servidor, nunca do corpo");

        // VARIANT 4: strict model rejects unknown fields (defense variant)
        System.out.println("[VARIANT] 4) Rejeitar campos desconhecidos (allowlist estrita)");
        String j4 = "{\"username\":\"mallory\",\"password\":\"x\",\"role\":\"ADMIN\"}";
        try { new ObjectMapper().readValue(j4, StrictAccount.class);
            System.out.println("[VULNERAVEL] (nao deveria chegar aqui)"); }
        catch (Exception e) { System.out.println("[DEFENDIDO] @JsonIgnoreProperties(ignoreUnknown=false) -> REJEITADO ("
                + e.getClass().getSimpleName() + ": campo 'role' desconhecido)"); }
    }
}
