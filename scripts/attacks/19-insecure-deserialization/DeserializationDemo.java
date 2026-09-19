// Self-contained Insecure Deserialization deep-dive (CWE-502). JDK + Jackson (classpath).
// Reimplemented from ysoserial/Log4Shell analyses & OWASP (see DEEP-DIVE.md).
// Run: java -cp "$(cat scripts/lib/classpath.txt)" DeserializationDemo.java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import java.io.*;
import java.util.Base64;

public class DeserializationDemo {
    // A stand-in "gadget": custom code runs during native deserialization.
    public static class Gadget implements Serializable {
        static String ran = null; String cmd;
        Gadget(String c){ this.cmd = c; }
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException { in.defaultReadObject(); ran = cmd; }
    }
    // A Jackson "gadget": instantiated when polymorphic default typing is enabled.
    public static class EvilBean { public static String ran = null; public EvilBean(){ ran = "instantiated-via-jackson"; } }

    static byte[] serialize(Object o) throws Exception { ByteArrayOutputStream b=new ByteArrayOutputStream();
        try(ObjectOutputStream os=new ObjectOutputStream(b)){ os.writeObject(o);} return b.toByteArray(); }

    public static void main(String[] args) throws Exception {
        Thread.currentThread().setContextClassLoader(DeserializationDemo.class.getClassLoader());
        // VARIANT 1: native readObject runs code
        System.out.println("[VARIANT] 1) readObject nativo executa codigo");
        Gadget.ran = null; byte[] bytes = serialize(new Gadget("echo pwned"));
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) { ois.readObject(); }
        System.out.println("[VULNERAVEL] apos readObject, codigo do gadget rodou: " + Gadget.ran);
        System.out.println("[DEFENDIDO] nao desserializar stream nativo nao confiavel (usar JSON p/ tipo fixo)");

        // VARIANT 2: ObjectInputFilter allowlist (JDK 9+) rejects unexpected classes
        System.out.println("[VARIANT] 2) ObjectInputFilter (allowlist de classes)");
        Gadget.ran = null; boolean blocked = false;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            ois.setObjectInputFilter(info -> info.serialClass()==null || info.serialClass()==Integer.class
                    ? ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED); // only Integer allowed
            ois.readObject();
        } catch (Exception e) { blocked = true; }
        System.out.println("[DEFENDIDO] filtro rejeitou a classe Gadget? " + blocked + " ; codigo rodou? " + (Gadget.ran != null));

        // VARIANT 3: Jackson polymorphic default typing instantiates attacker-named type
        System.out.println("[VARIANT] 3) Jackson polimorfico (default typing)");
        EvilBean.ran = null;
        String json = "[\"" + EvilBean.class.getName() + "\",{}]";
        ObjectMapper unsafe = new ObjectMapper();
        unsafe.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        Object o = unsafe.readValue(json, Object.class);
        System.out.println("[VULNERAVEL] default typing instanciou " + o.getClass().getSimpleName() + " -> " + EvilBean.ran);
        EvilBean.ran = null;
        ObjectMapper safe = new ObjectMapper(); // no default typing
        try { safe.readValue(json, java.util.Map.class); } catch (Exception ignored) {}
        System.out.println("[DEFENDIDO] sem default typing + tipo fixo -> instanciou EvilBean? " + (EvilBean.ran != null));
    }
}
