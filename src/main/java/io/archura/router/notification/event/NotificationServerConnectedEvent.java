package io.archura.router.notification.event;

import org.springframework.context.ApplicationEvent;

import java.net.http.WebSocket;

public class NotificationServerConnectedEvent extends ApplicationEvent {
    public NotificationServerConnectedEvent(final WebSocket.Listener listener) {
        super(listener);
    }

    @Override
    public WebSocket.Listener getSource() {
        return (WebSocket.Listener) super.getSource();
    }
}
