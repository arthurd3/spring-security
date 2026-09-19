// Self-contained Path Traversal deep-dive (CWE-22). JDK-only; uses a temp directory. Incl. Zip Slip.
// Reimplemented from OWASP / Snyk Zip Slip (see DEEP-DIVE.md). Run: java PathTraversalDemo
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class PathTraversalDemo {
    static Path base;

    static String vulnRead(String name) throws IOException { return Files.readString(base.resolve(name)); }
    static String safeRead(String name) {
        try {
            Path target = base.resolve(name).normalize();
            if (!target.startsWith(base)) return "400: caminho escapa do diretorio publico";
            if (!Files.isRegularFile(target)) return "404: nao encontrado";
            return Files.readString(target);
        } catch (Exception e) { return "400: " + e.getClass().getSimpleName(); }
    }
    // Zip Slip: extracting an archive entry whose name contains ../
    static String extractEntry(String entryName, boolean safe) {
        Path target = base.resolve(entryName).normalize();
        if (safe && !target.startsWith(base)) return "400: entrada de zip escapa (Zip Slip barrado)";
        return "gravaria em: " + target;
    }

    public static void main(String[] args) throws Exception {
        base = Files.createTempDirectory("public");
        Files.writeString(base.resolve("readme.txt"), "conteudo publico");
        Files.writeString(base.getParent().resolve("secrets.txt"), "db.password=super-secret");

        // VARIANT 1: basic ../
        System.out.println("[VARIANT] 1) ../ basico");
        System.out.println("[VULNERAVEL] name=../secrets.txt -> " + vulnRead("../secrets.txt"));
        System.out.println("[DEFENDIDO] safeRead(../secrets.txt) -> " + safeRead("../secrets.txt"));

        // VARIANT 2: URL-encoded (decoded before use)
        System.out.println("[VARIANT] 2) URL-encoded  %2e%2e%2f");
        String enc = "%2e%2e%2fsecrets.txt";
        String decoded = URLDecoder.decode(enc, StandardCharsets.UTF_8); // servers decode first
        System.out.println("[VULNERAVEL] name=" + enc + " (decodifica p/ " + decoded + ") -> " + vulnRead(decoded));
        System.out.println("[DEFENDIDO] safeRead(decoded) -> " + safeRead(decoded));

        // VARIANT 3: absolute path (resolve() discards the base!)
        System.out.println("[VARIANT] 3) Caminho absoluto");
        String abs = base.getParent().resolve("secrets.txt").toString();
        System.out.println("[VULNERAVEL] name=<absoluto> -> " + vulnRead(abs) + "  (resolve() com absoluto ignora a base)");
        System.out.println("[DEFENDIDO] safeRead(<absoluto>) -> " + safeRead(abs));

        // VARIANT 4: Zip Slip (archive entry with ../)
        System.out.println("[VARIANT] 4) Zip Slip  (entrada de arquivo com ../)");
        System.out.println("[VULNERAVEL] " + extractEntry("../../tmp/evil.sh", false));
        System.out.println("[DEFENDIDO] " + extractEntry("../../tmp/evil.sh", true));

        // legit
        System.out.println("[VARIANT] 5) Uso legitimo");
        System.out.println("[DEFENDIDO] safeRead(readme.txt) -> " + safeRead("readme.txt"));
    }
}
