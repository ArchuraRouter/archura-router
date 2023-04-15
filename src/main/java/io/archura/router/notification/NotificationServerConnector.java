package io.archura.router.notification;

import io.archura.router.config.GlobalConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;

import static java.util.Objects.nonNull;

@Slf4j
@RequiredArgsConstructor
@Component
public class NotificationServerConnector {

    private final GlobalConfiguration globalConfiguration;
    private final NotificationServerListener notificationServerListener;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .executor(Executors.newVirtualThreadPerTaskExecutor())
            .build();
    private final ByteBuffer pingMessage = ByteBuffer.allocate(0);

    public void connect() {
        Thread.ofVirtual().start(() -> {
            // connect to notification server or continue to retry
            while (Thread.currentThread().isAlive()) {
                connectToWebsocket();
            }
        });
    }

    private void connectToWebsocket() {
        WebSocket webSocket = null;
        try {
            final WebSocket.Builder webSocketBuilder = createWebsocketBuilder();
            webSocket = connectToWebsocket(webSocketBuilder);
            log.debug("Connection established to notification server");
            // send ping to notification server, this will fail if the connection is lost
            while (nonNull(webSocket)) {
                sendPingToServer(webSocket);
            }
        } catch (Exception e) {
            final String error = "Failed to connect to notification server, url: '%s', exception: '%s', message: '%s'"
                    .formatted(
                            globalConfiguration.getNotificationServerURL(),
                            e.getClass().getSimpleName(),
                            e.getMessage()
                    );
            log.error(error);
            if (nonNull(webSocket)) {
                notificationServerListener.onError(webSocket, e);
                notificationServerListener.onClose(webSocket, 0, "Connection closed");
            }
            waitAndContinue();
        }
    }

    private WebSocket.Builder createWebsocketBuilder() {
        WebSocket.Builder webSocketBuilder = httpClient.newWebSocketBuilder();
        for (Map.Entry<String, String> entry : globalConfiguration.getNotificationServerRequestHeaders().entrySet()) {
            webSocketBuilder = webSocketBuilder.header(entry.getKey(), entry.getValue());
        }
        return webSocketBuilder;
    }

    private WebSocket connectToWebsocket(final WebSocket.Builder webSocketBuilder) {
        final URI notificationServerURL = URI.create(globalConfiguration.getNotificationServerURL());
        return webSocketBuilder
                .connectTimeout(Duration.ofMillis(globalConfiguration.getNotificationServerConnectionTimeout()))
                .buildAsync(notificationServerURL, notificationServerListener)
                .join();
    }

    private void sendPingToServer(final WebSocket webSocket) {
        waitAndContinue();
        webSocket.sendPing(pingMessage).join();
    }

    private void waitAndContinue() {
        try {
            Thread.sleep(globalConfiguration.getNotificationServerRetryInterval());
        } catch (InterruptedException interruptedException) {
            log.error("Failed to sleep", interruptedException);
        }
    }
}
