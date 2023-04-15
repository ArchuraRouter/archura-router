package io.archura.router.notification.event;

import org.springframework.context.ApplicationEvent;

import java.net.http.WebSocket;

public class NotificationServerDisconnectedEvent extends ApplicationEvent {
    private final int statusCode;
    private final String reason;

    public NotificationServerDisconnectedEvent(
            final WebSocket.Listener listener,
            final int statusCode,
            final String reason
    ) {
        super(listener);
        this.statusCode = statusCode;
        this.reason = reason;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getReason() {
        return reason;
    }

    @Override
    public WebSocket.Listener getSource() {
        return (WebSocket.Listener) super.getSource();
    }
}
