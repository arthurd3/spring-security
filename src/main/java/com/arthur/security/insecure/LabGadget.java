package com.arthur.security.insecure;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * A tiny, SAFE stand-in for a real deserialization "gadget".
 *
 * <p>Real attacks chain library classes (e.g. Commons-Collections) whose {@code readObject} logic can
 * be steered into running arbitrary commands. Adding such a library here would make this repo itself
 * dangerous, so this class only demonstrates the mechanism that makes those chains possible:
 * <b>custom code runs during deserialization</b>. Its {@code readObject} records a marker instead of
 * executing anything - but that marker proves the attacker's object graph got to run code inside the
 * server merely by being deserialized.
 */
public class LabGadget implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Set by {@link #readObject} so the endpoint can prove custom code executed during deserialization. */
    public static volatile String lastSideEffect = null;

    private String command;

    public LabGadget(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // In a real gadget this is where exec() would happen. We only record that it ran.
        lastSideEffect = command;
    }

    public String getCommand() {
        return command;
    }
}
