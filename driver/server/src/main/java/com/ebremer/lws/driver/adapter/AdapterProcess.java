// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

import com.ebremer.lws.driver.DriverException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * One running adapter: a child process that speaks {@code lws-driver/1} (driver/PROTOCOL.md) on its standard
 * streams. Requests go one at a time, as the protocol requires; the process's stderr is kept as its log.
 */
public final class AdapterProcess implements AutoCloseable {

    public static final String PROTOCOL = "lws-driver/1";

    private static final Logger LOG = LoggerFactory.getLogger(AdapterProcess.class);
    private static final int LOG_LINES = 2000;
    private static final Duration SHUTDOWN_GRACE = Duration.ofSeconds(5);

    private final String name;
    private final Process process;
    private final JsonMapper json;
    private final BufferedWriter stdin;
    private final CompletableFuture<Hello> hello = new CompletableFuture<>();
    private final Map<Long, CompletableFuture<ObjectNode>> pending = new ConcurrentHashMap<>();
    private final Deque<String> log = new ArrayDeque<>();
    private final AtomicLong nextId = new AtomicLong(1);
    private final ReentrantLock turn = new ReentrantLock();
    private volatile boolean stopped;

    private AdapterProcess(String name, Process process, JsonMapper json) {
        this.name = name;
        this.process = process;
        this.json = json;
        this.stdin = new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
        daemon(name + "-stdout", this::readResponses).start();
        daemon(name + "-stderr", this::readLog).start();
        process.onExit().thenAccept(p -> fail(new DriverException(name + " exited with status " + p.exitValue()
                + lastLog())));
    }

    /**
     * Starts an adapter and waits for its hello.
     *
     * @param name a name for logs and threads, such as {@code java-3f9a2c}
     * @param command the command line; the first element, when it is a relative path, resolves against {@code directory}
     * @param directory the working directory
     * @param environment extra environment variables
     */
    public static AdapterProcess start(String name, List<String> command, Path directory, Map<String, String> environment,
            JsonMapper json, Duration startupTimeout) {
        if (command.isEmpty()) {
            throw new DriverException("no command is configured for " + name);
        }
        List<String> resolved = new ArrayList<>(command);
        resolved.set(0, Commands.executable(command.get(0), directory));
        ProcessBuilder builder = new ProcessBuilder(resolved).directory(directory.toFile());
        builder.environment().putAll(environment);
        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            throw new DriverException("cannot start " + name + " (" + String.join(" ", resolved) + "): " + e.getMessage(), e);
        }
        AdapterProcess adapter = new AdapterProcess(name, process, json);
        try {
            adapter.hello.get(startupTimeout.toMillis(), TimeUnit.MILLISECONDS);
            return adapter;
        } catch (TimeoutException e) {
            adapter.kill();
            throw new DriverException(name + " did not say hello within " + startupTimeout.toSeconds() + " s" + adapter.lastLog());
        } catch (ExecutionException e) {
            adapter.kill();
            throw e.getCause() instanceof DriverException d ? d : new DriverException(e.getCause().getMessage(), e.getCause());
        } catch (InterruptedException e) {
            adapter.kill();
            Thread.currentThread().interrupt();
            throw new DriverException("interrupted while starting " + name, e);
        }
    }

    /** What the adapter announced. */
    public Hello hello() {
        return hello.join();
    }

    public String name() {
        return name;
    }

    public boolean isAlive() {
        return !stopped && process.isAlive();
    }

    /**
     * Sends a request and waits for its response, {@code {"ok": true, "result": …}} or
     * {@code {"ok": false, "error": …}}, without the {@code id}.
     *
     * @throws DriverException when the adapter is gone, or does not answer in time (it is then stopped)
     */
    public ObjectNode call(String op, ObjectNode args, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        try {
            if (!turn.tryLock(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                throw new DriverException(name + " is still busy with an earlier request after " + timeout.toSeconds() + " s");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DriverException("interrupted while waiting for " + name, e);
        }
        try {
            if (!isAlive()) {
                throw new DriverException(name + " is not running" + lastLog());
            }
            long id = nextId.getAndIncrement();
            CompletableFuture<ObjectNode> response = new CompletableFuture<>();
            pending.put(id, response);
            ObjectNode request = json.createObjectNode();
            request.put("id", id);
            request.put("op", op);
            request.set("args", args);
            try {
                stdin.write(json.writeValueAsString(request));
                stdin.write('\n');
                stdin.flush();
            } catch (IOException e) {
                pending.remove(id);
                throw new DriverException("cannot write to " + name + ": " + e.getMessage() + lastLog(), e);
            }
            try {
                long left = Math.max(1, deadline - System.nanoTime());
                ObjectNode message = response.get(left, TimeUnit.NANOSECONDS);
                message.remove("id");
                return message;
            } catch (TimeoutException e) {
                pending.remove(id);
                kill();
                throw new DriverException(name + " gave no answer to " + op + " within " + timeout.toSeconds()
                        + " s, and was stopped" + lastLog());
            } catch (ExecutionException e) {
                throw e.getCause() instanceof DriverException d ? d : new DriverException(e.getCause().getMessage(), e.getCause());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new DriverException("interrupted while waiting for " + name, e);
            }
        } finally {
            turn.unlock();
        }
    }

    /** The last {@code max} lines the adapter wrote to stderr, and the driver's notes about it. */
    public List<String> log(int max) {
        synchronized (log) {
            List<String> lines = new ArrayList<>(log);
            return lines.subList(Math.max(0, lines.size() - max), lines.size());
        }
    }

    /** Asks the adapter to shut down, and stops it if it does not. */
    @Override
    public void close() {
        if (isAlive()) {
            try {
                call("shutdown", json.createObjectNode(), SHUTDOWN_GRACE);
                process.waitFor(SHUTDOWN_GRACE.toMillis(), TimeUnit.MILLISECONDS);
            } catch (DriverException e) {
                LOG.debug("{} did not shut down cleanly: {}", name, e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        kill();
    }

    private void kill() {
        stopped = true;
        if (process.isAlive()) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
        }
    }

    private void readResponses() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    onLine(line);
                }
            }
        } catch (IOException e) {
            note("stdout closed: " + e.getMessage());
        }
    }

    private void onLine(String line) {
        JsonNode message;
        try {
            message = json.readTree(line);
        } catch (JacksonException e) {
            note("stdout line that is not JSON, ignored: " + abbreviate(line));
            return;
        }
        if (!(message instanceof ObjectNode object)) {
            note("stdout line that is not a JSON object, ignored: " + abbreviate(line));
            return;
        }
        JsonNode helloNode = object.get("hello");
        if (helloNode != null) {
            try {
                Hello h = Hello.of(helloNode);
                if (!PROTOCOL.equals(h.protocol())) {
                    hello.completeExceptionally(new DriverException(name + " speaks " + h.protocol() + ", not " + PROTOCOL));
                } else {
                    hello.complete(h);
                }
            } catch (IllegalArgumentException e) {
                hello.completeExceptionally(new DriverException(name + " sent a malformed hello: " + e.getMessage()));
            }
            return;
        }
        JsonNode id = object.get("id");
        CompletableFuture<ObjectNode> waiter = id != null && id.canConvertToLong() ? pending.remove(id.asLong()) : null;
        if (waiter == null) {
            note("response to no pending request, ignored: " + abbreviate(line));
            return;
        }
        if (!object.path("ok").isBoolean() || !(object.has("result") || object.has("error"))) {
            waiter.completeExceptionally(new DriverException(name + " sent a malformed response: " + abbreviate(line)));
            return;
        }
        waiter.complete(object);
    }

    private void readLog() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                append(line);
                LOG.debug("{}: {}", name, line);
            }
        } catch (IOException e) {
            // The process ended.
        }
    }

    private void note(String message) {
        LOG.warn("{}: {}", name, message);
        append("[driver] " + message);
    }

    private void append(String line) {
        synchronized (log) {
            if (log.size() == LOG_LINES) {
                log.removeFirst();
            }
            log.addLast(line);
        }
    }

    private void fail(DriverException e) {
        hello.completeExceptionally(e);
        pending.values().forEach(f -> f.completeExceptionally(e));
        pending.clear();
    }

    private String lastLog() {
        List<String> tail = log(20);
        return tail.isEmpty() ? "" : "; its log ends:\n" + String.join("\n", tail);
    }

    private static String abbreviate(String line) {
        return line.length() > 300 ? line.substring(0, 300) + "…" : line;
    }

    private static Thread daemon(String name, Runnable body) {
        Thread thread = new Thread(body, name);
        thread.setDaemon(true);
        return thread;
    }
}
