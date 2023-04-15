package io.archura.router.filter.exception;

public class ArchuraFilterException extends RuntimeException {

    private static final int HTTP_STATUS_500 = 500;
    private int statusCode = HTTP_STATUS_500;

    public ArchuraFilterException(final Throwable cause) {
        super(cause);
    }

    public ArchuraFilterException(final int statusCode, final String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public ArchuraFilterException(final int statusCode, final String message, final Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }

}
