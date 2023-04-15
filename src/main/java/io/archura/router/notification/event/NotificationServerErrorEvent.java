package io.archura.router.notification.event;

import org.springframework.context.ApplicationEvent;

import java.net.http.WebSocket;

public class NotificationServerErrorEvent extends ApplicationEvent {
    private final Throwable error;

    public NotificationServerErrorEvent(final WebSocket.Listener listener, final Throwable error) {
        super(listener);
        this.error = error;
    }

    public Throwable getError() {
        return error;
    }

    @Override
    public WebSocket.Listener getSource() {
        return (WebSocket.Listener) super.getSource();
    }
}
