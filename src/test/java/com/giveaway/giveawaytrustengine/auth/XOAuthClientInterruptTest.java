package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.config.XOAuthProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chunk 4 review, item 5: {@code XOAuthClient.send} must restore the thread's interrupt flag
 * before rethrowing on {@code InterruptedException} -- swallowing it without restoring it can
 * mask cooperative cancellation/shutdown signals for whatever thread was handling the login.
 *
 * A real blocking socket that accepts a connection and never responds, so the JDK
 * {@code HttpClient}'s synchronous {@code send} is genuinely blocked waiting on a response (not
 * yet timed out) when the test interrupts the calling thread -- a real {@code InterruptedException}
 * from the JDK, not a simulated one.
 */
class XOAuthClientInterruptTest {

    private ServerSocket serverSocket;

    @AfterEach
    void closeServer() throws Exception {
        if (serverSocket != null) {
            serverSocket.close();
        }
    }

    @Test
    void interruptDuringUserLookupRestoresTheInterruptFlag() throws Exception {
        serverSocket = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            try (Socket accepted = serverSocket.accept()) {
                // Accept the connection, then just hold it open -- never write a response, so
                // the HttpClient's synchronous send() stays genuinely blocked.
                Thread.sleep(10_000);
            }
            catch (Exception ignoredSocketClosedOrInterrupted) {
                // Test teardown closes the server socket -- this is expected, not a failure.
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();

        XOAuthProperties properties = new XOAuthProperties(
                "client-id", "client-secret", "http://localhost/auth/callback",
                "https://x.com/i/oauth2/authorize",
                "http://127.0.0.1:" + serverSocket.getLocalPort() + "/2/oauth2/token",
                "http://127.0.0.1:" + serverSocket.getLocalPort() + "/2/users/me",
                Duration.ofSeconds(5), Duration.ofSeconds(30));
        XOAuthClient client = new XOAuthClient(properties);

        AtomicReference<Throwable> caught = new AtomicReference<>();
        AtomicBoolean interruptFlagSeenInsideWorker = new AtomicBoolean(false);

        Thread worker = new Thread(() -> {
            try {
                client.lookupUser("some-x-access-token");
            }
            catch (Throwable t) {
                caught.set(t);
            }
            finally {
                // Must be read on THIS thread, before it terminates -- the interrupt status
                // does not survive past the thread's own lifetime.
                interruptFlagSeenInsideWorker.set(Thread.currentThread().isInterrupted());
            }
        });
        worker.start();

        // Give the worker time to actually reach the blocked read (connect, send the request,
        // start waiting on the response) before interrupting it.
        Thread.sleep(500);
        worker.interrupt();
        worker.join(5000);

        assertThat(caught.get())
                .as("the blocked call must fail with this app's own exception type")
                .isInstanceOf(OAuthExchangeException.class);
        assertThat(interruptFlagSeenInsideWorker.get())
                .as("Thread.currentThread().interrupt() must be called before rethrowing, "
                        + "so the interrupt signal is never silently swallowed")
                .isTrue();
    }
}
