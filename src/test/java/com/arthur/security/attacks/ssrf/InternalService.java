package com.arthur.security.attacks.ssrf;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * A throwaway HTTP server bound to loopback, standing in for the kind of service an SSRF is aimed at:
 * a cloud metadata endpoint, an internal admin API, something listening only on 127.0.0.1.
 *
 * <p>It makes the demo honest - the attack really does retrieve data over HTTP - while keeping the
 * test hermetic, since nothing leaves the machine.
 */
final class InternalService implements AutoCloseable {

    static final String SECRET = "INTERNAL-CREDENTIAL-b7f2";

    private final HttpServer server;

    private InternalService(HttpServer server) {
        this.server = server;
    }

    static InternalService start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/latest/meta-data/credentials", exchange -> {
            byte[] body = SECRET.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        return new InternalService(server);
    }

    String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/latest/meta-data/credentials";
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
