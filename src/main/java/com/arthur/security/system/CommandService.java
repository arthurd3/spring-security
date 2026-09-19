package com.arthur.security.system;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.regex.Pattern;

/**
 * The safe way to act on a user-supplied host name (OWASP A03:2021, CWE-78 - OS command injection).
 *
 * <p>The real fix has two parts, and the first is the important one:
 * <ol>
 *   <li><b>Never hand user input to a shell.</b> {@code sh -c "ping " + host} lets the shell interpret
 *       {@code ;}, {@code |}, {@code &&}, backticks and {@code $(...)}, so {@code host="x; rm -rf /"}
 *       runs a second command. Building an argument list for {@link ProcessBuilder} (no {@code sh -c})
 *       already removes the shell as an interpreter.</li>
 *   <li><b>Validate against a strict allowlist</b> anyway. A host name is only letters, digits, dots
 *       and hyphens - so anything else is rejected before it goes anywhere near a process.</li>
 * </ol>
 *
 * <p>This service does not actually spawn {@code ping} - that would make the test depend on the host
 * OS. The security-relevant behaviour is the validation: a metacharacter-bearing input is refused.
 */
@Service
public class CommandService {

    /** RFC-1123-ish host label check: letters, digits, dot and hyphen only. No shell metacharacters. */
    private static final Pattern SAFE_HOST = Pattern.compile("^[a-zA-Z0-9.-]{1,253}$");

    public String ping(String host) {
        if (host == null || !SAFE_HOST.matcher(host).matches()) {
            // Refused before any command is built - the injection never reaches an interpreter.
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid host");
        }
        // A real implementation would use new ProcessBuilder("ping", "-c", "1", host).start()
        // (an argument list, never "sh -c ..."). The validated host is safe to report back.
        return "host " + host + " aceito para verificacao (execucao simulada, sem shell)";
    }
}
