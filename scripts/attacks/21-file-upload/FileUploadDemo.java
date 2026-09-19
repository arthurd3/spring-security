// Self-contained Unrestricted File Upload deep-dive (CWE-434). JDK-only.
// Reimplemented from OWASP File Upload / PayloadsAllTheThings (see DEEP-DIVE.md). Run: java FileUploadDemo
import java.util.Set;

public class FileUploadDemo {
    static final Set<String> ALLOWED = Set.of("png","jpg","jpeg","gif","txt","pdf");
    static final byte[] PNG_MAGIC = {(byte)0x89,'P','N','G'};

    static String ext(String n){ int d=n.lastIndexOf('.'); return d<0?"":n.substring(d+1).toLowerCase(); }
    static String baseName(String n){ int s=Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\')); return n.substring(s+1); }
    static boolean magicIsPng(byte[] b){ if(b.length<4) return false; for(int i=0;i<4;i++) if(b[i]!=PNG_MAGIC[i]) return false; return true; }

    // BUG: keep client filename; serve by extension.
    static String vulnStore(String filename, String contentType){
        String type = ext(filename).equals("html")||ext(filename).equals("jsp") ? "EXECUTAVEL" : "estatico";
        return "gravado como '" + filename + "' (servido como " + type + ")";
    }
    // FIX: allowlist ext + validate magic bytes + random name + strip path.
    static String safeStore(String filename, String contentType, byte[] content){
        String name = baseName(filename);                 // strip any path
        String e = ext(name);
        if (!ALLOWED.contains(e)) return "400: extensao '." + e + "' nao permitida";
        if ((e.equals("png")) && !magicIsPng(content)) return "400: conteudo nao e PNG (magic bytes) - content-type ignorado";
        return "gravado como '" + Integer.toHexString(name.hashCode()) + "." + e + "' (nome aleatorio, fora do webroot)";
    }

    public static void main(String[] args) {
        // VARIANT 1: dangerous extension
        System.out.println("[VARIANT] 1) Extensao perigosa (.jsp/.html)");
        System.out.println("[VULNERAVEL] " + vulnStore("shell.jsp", "application/octet-stream"));
        System.out.println("[DEFENDIDO] " + safeStore("shell.jsp", "image/png", new byte[]{1,2,3,4}));

        // VARIANT 2: double extension / trailing dot
        System.out.println("[VARIANT] 2) Dupla extensao / ponto final");
        System.out.println("[VULNERAVEL] " + vulnStore("shell.jsp.png", "image/png") + "  (servidor mal-config executa .jsp)");
        System.out.println("[DEFENDIDO] so a extensao final na allowlist + nome aleatorio -> " + safeStore("shell.jsp.png", "image/png", PNG_MAGIC));

        // VARIANT 3: content-type spoof vs magic bytes
        System.out.println("[VARIANT] 3) Content-Type falso vs magic bytes");
        byte[] notPng = "<?php system($_GET[0]); ?>".getBytes();
        System.out.println("[VULNERAVEL] confia no Content-Type: image/png -> aceito, mas o conteudo e PHP");
        System.out.println("[DEFENDIDO] " + safeStore("evil.png", "image/png", notPng));

        // VARIANT 4: path in filename
        System.out.println("[VARIANT] 4) Caminho no nome do arquivo");
        System.out.println("[VULNERAVEL] " + vulnStore("../../webapps/ROOT/shell.jsp", "x") + "  (grava fora do diretorio)");
        System.out.println("[DEFENDIDO] " + safeStore("../../webapps/ROOT/shell.jsp", "x", new byte[]{1}) + "  (path removido + allowlist)");

        // legit
        System.out.println("[VARIANT] 5) Uso legitimo");
        System.out.println("[DEFENDIDO] " + safeStore("avatar.png", "image/png", PNG_MAGIC));
    }
}
