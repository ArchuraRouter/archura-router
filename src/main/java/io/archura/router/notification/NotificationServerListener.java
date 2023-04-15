package io.archura.router.notification;

import io.archura.router.notification.event.NotificationServerConnectedEvent;
import io.archura.router.notification.event.NotificationServerDisconnectedEvent;
import io.archura.router.notification.event.NotificationServerErrorEvent;
import io.archura.router.notification.event.NotificationServerTextMessageEvent;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.net.http.WebSocket;
import java.util.concurrent.CompletionStage;

@Slf4j
@AllArgsConstructor
@Component
public class NotificationServerListener implements WebSocket.Listener {

    private final ApplicationEventPublisher publisher;

    @Override
    public void onOpen(final WebSocket webSocket) {
        log.debug("Connected to notification server");
        Thread.startVirtualThread(() -> publisher.publishEvent(new NotificationServerConnectedEvent(this)));
    }

    @Override
    public CompletionStage<?> onText(final WebSocket webSocket, final CharSequence data, final boolean last) {
        log.debug("Received notification from notification server: {}", data);
        Thread.startVirtualThread(() ->
                publisher.publishEvent(new NotificationServerTextMessageEvent(this, data.toString())));
        return null;
    }

    @Override
    public CompletionStage<?> onClose(final WebSocket webSocket, final int statusCode, final String reason) {
        log.debug("Disconnected from notification server");
        Thread.startVirtualThread(() ->
                publisher.publishEvent(new NotificationServerDisconnectedEvent(this, statusCode, reason)));
        return null;
    }

    @Override
    public void onError(final WebSocket webSocket, final Throwable error) {
        log.error("Error occurred while communicating with notification server", error);
        Thread.startVirtualThread(() -> publisher.publishEvent(new NotificationServerErrorEvent(this, error)));
    }

}
