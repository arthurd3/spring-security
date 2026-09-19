// Self-contained Sensitive Data Exposure deep-dive (CWE-200). Uses Jackson (classpath).
// Reimplemented from OWASP guidance (see DEEP-DIVE.md).
// Run: java -cp "$(cat scripts/lib/classpath.txt)" DataExposureDemo.java
import com.fasterxml.jackson.databind.ObjectMapper;

public class DataExposureDemo {
    // Persistence entity: every getter is serialized by default.
    public static class UserEntity {
        public long getId(){return 7;}
        public String getUsername(){return "arthur";}
        public String getPasswordHash(){return "{bcrypt}$2a$10$abcd....";}
        public String getResetToken(){return "R-9f8e7d";}
        public String getSsn(){return "123-45-6789";}
        public String getRole(){return "USER";}
    }
    public record UserProfile(String username, String role) {} // safe projection

    static String maskEmail(String e){ int at=e.indexOf('@'); return at<2?"***":e.charAt(0)+"***"+e.substring(at); }

    public static void main(String[] args) throws Exception {
        ObjectMapper om = new ObjectMapper();

        // VARIANT 1: returning the entity leaks hash/token/SSN
        System.out.println("[VARIANT] 1) Serializar a entidade");
        System.out.println("[VULNERAVEL] " + om.writeValueAsString(new UserEntity()));
        System.out.println("[DEFENDIDO] " + om.writeValueAsString(new UserProfile("arthur","USER")) + "  (DTO: so o publico)");

        // VARIANT 2: verbose error / stack trace leaks internals
        System.out.println("[VARIANT] 2) Erro verboso / stack trace");
        String verbose = "500: org.h2.jdbc.JdbcSQLException: Table \"USERS\" not found; SQL=[SELECT * FROM users WHERE ...] at com.arthur...";
        System.out.println("[VULNERAVEL] " + verbose + "  (vaza stack, SQL, tecnologia)");
        System.out.println("[DEFENDIDO] 500: {\"error\":\"Internal Server Error\",\"id\":\"req-abc123\"}  (id p/ correlacionar no log)");

        // VARIANT 3: excessive fields (return more than the client needs)
        System.out.println("[VARIANT] 3) Campos excessivos");
        System.out.println("[VULNERAVEL] /api/users retorna internalNotes, creditScore, isFlagged...  (over-exposure)");
        System.out.println("[DEFENDIDO] retornar so os campos necessarios ao caso de uso (DTO por endpoint)");

        // VARIANT 4: PII in logs
        System.out.println("[VARIANT] 4) PII em log");
        System.out.println("[VULNERAVEL] log.info(\"login user=arthur@example.com card=4111111111111111\")  (PII em claro)");
        System.out.println("[DEFENDIDO] log.info(\"login user=" + maskEmail("arthur@example.com") + " card=**** **** **** 1111\")");

        // VARIANT 5: debug endpoints / .git / actuator exposure
        System.out.println("[VARIANT] 5) Endpoints de debug / .git / actuator");
        System.out.println("[VULNERAVEL] /actuator/env, /actuator/heapdump, /.git/ acessiveis -> segredos/codigo");
        System.out.println("[DEFENDIDO] expor so /actuator/health; proteger o resto; nao publicar .git; secrets fora do artefato");
    }
}
