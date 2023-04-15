package io.archura.router.compat;

import org.slf4j.Logger;

import static java.util.Objects.isNull;

public class LoggerDecorator implements io.archura.router.compat.Logger {

    private final String domain;
    private final String tenant;
    private final Logger log;

    public LoggerDecorator(final String domain, final String tenant, final Logger log) {
        this.domain = domain;
        this.tenant = tenant;
        this.log = log;
    }

    public LoggerDecorator(final Logger log) {
        this.domain = null;
        this.tenant = null;
        this.log = log;
    }

    private String format(final String msg) {
        if (isNull(domain) || isNull(tenant)) {
            return msg;
        }
        return String.format("[%s][%s] %s", domain, tenant, msg);
    }

    /**
     * Log a message at the TRACE level.
     *
     * @param msg the message string to be logged
     */
    @Override
    public void trace(final String msg) {
        log.trace(format(msg));
    }

    /**
     * Log a message at the TRACE level according to the specified format
     * and argument.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the TRACE level.
     *
     * @param format the format string
     * @param arg    the argument
     */
    @Override
    public void trace(final String format, final Object arg) {
        log.trace(format(format), arg);
    }

    /**
     * Log a message at the TRACE level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the TRACE level.
     *
     * @param format the format string
     * @param arg1   the first argument
     * @param arg2   the second argument
     */
    @Override
    public void trace(final String format, final Object arg1, final Object arg2) {
        log.trace(format(format), arg1, arg2);
    }


    /**
     * Log a message at the TRACE level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous string concatenation when the logger
     * is disabled for the TRACE level. However, this variant incurs the hidden
     * (and relatively small) cost of creating an <code>Object[]</code> before invoking the method,
     * even if this logger is disabled for TRACE. The variants taking {@link #trace(String, Object) one} and
     * {@link #trace(String, Object, Object) two} arguments exist solely in order to avoid this hidden cost.
     *
     * @param format    the format string
     * @param arguments a list of 3 or more arguments
     */
    @Override
    public void trace(final String format, final Object... arguments) {
        log.trace(format(format), arguments);
    }

    /**
     * Log an exception (throwable) at the TRACE level with an
     * accompanying message.
     *
     * @param msg       the message accompanying the exception
     * @param throwable the exception (throwable) to log
     */
    @Override
    public void trace(final String msg, final Throwable throwable) {
        log.trace(format(msg), throwable);
    }

    /**
     * Log a message at the DEBUG level.
     *
     * @param msg the message string to be logged
     */
    @Override
    public void debug(final String msg) {
        log.debug(format(msg));
    }

    /**
     * Log a message at the DEBUG level according to the specified format
     * and argument.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the DEBUG level.
     *
     * @param format the format string
     * @param arg    the argument
     */
    @Override
    public void debug(final String format, final Object arg) {
        log.debug(format(format), arg);
    }

    /**
     * Log a message at the DEBUG level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the DEBUG level.
     *
     * @param format the format string
     * @param arg1   the first argument
     * @param arg2   the second argument
     */
    @Override
    public void debug(final String format, final Object arg1, final Object arg2) {
        log.debug(format(format), arg1, arg2);
    }

    /**
     * Log a message at the DEBUG level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous string concatenation when the logger
     * is disabled for the DEBUG level. However, this variant incurs the hidden
     * (and relatively small) cost of creating an <code>Object[]</code> before invoking the method,
     * even if this logger is disabled for DEBUG. The variants taking
     * {@link #debug(String, Object) one} and {@link #debug(String, Object, Object) two}
     * arguments exist solely in order to avoid this hidden cost.
     *
     * @param format    the format string
     * @param arguments a list of 3 or more arguments
     */
    @Override
    public void debug(final String format, final Object... arguments) {
        log.debug(format(format), arguments);
    }

    /**
     * Log an exception (throwable) at the DEBUG level with an
     * accompanying message.
     *
     * @param msg       the message accompanying the exception
     * @param throwable the exception (throwable) to log
     */
    @Override
    public void debug(final String msg, final Throwable throwable) {
        log.debug(format(msg), throwable);
    }

    /**
     * Log a message at the INFO level.
     *
     * @param msg the message string to be logged
     */
    @Override
    public void info(final String msg) {
        log.info(format(msg));
    }

    /**
     * Log a message at the INFO level according to the specified format
     * and argument.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the INFO level.
     *
     * @param format the format string
     * @param arg    the argument
     */
    @Override
    public void info(final String format, final Object arg) {
        log.info(format(format), arg);
    }

    /**
     * Log a message at the INFO level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the INFO level.
     *
     * @param format the format string
     * @param arg1   the first argument
     * @param arg2   the second argument
     */
    @Override
    public void info(final String format, final Object arg1, final Object arg2) {
        log.info(format(format), arg1, arg2);
    }

    /**
     * Log a message at the INFO level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous string concatenation when the logger
     * is disabled for the INFO level. However, this variant incurs the hidden
     * (and relatively small) cost of creating an <code>Object[]</code> before invoking the method,
     * even if this logger is disabled for INFO. The variants taking
     * {@link #info(String, Object) one} and {@link #info(String, Object, Object) two}
     * arguments exist solely in order to avoid this hidden cost.
     *
     * @param format    the format string
     * @param arguments a list of 3 or more arguments
     */
    @Override
    public void info(final String format, final Object... arguments) {
        log.info(format(format), arguments);
    }

    /**
     * Log an exception (throwable) at the INFO level with an
     * accompanying message.
     *
     * @param msg       the message accompanying the exception
     * @param throwable the exception (throwable) to log
     */
    @Override
    public void info(final String msg, final Throwable throwable) {
        log.info(format(msg), throwable);
    }


    /**
     * Log a message at the WARN level.
     *
     * @param msg the message string to be logged
     */
    @Override
    public void warn(final String msg) {
        log.warn(format(msg));
    }

    /**
     * Log a message at the WARN level according to the specified format
     * and argument.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the WARN level.
     *
     * @param format the format string
     * @param arg    the argument
     */
    @Override
    public void warn(final String format, final Object arg) {
        log.warn(format(format), arg);
    }

    /**
     * Log a message at the WARN level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous string concatenation when the logger
     * is disabled for the WARN level. However, this variant incurs the hidden
     * (and relatively small) cost of creating an <code>Object[]</code> before invoking the method,
     * even if this logger is disabled for WARN. The variants taking
     * {@link #warn(String, Object) one} and {@link #warn(String, Object, Object) two}
     * arguments exist solely in order to avoid this hidden cost.
     *
     * @param format    the format string
     * @param arguments a list of 3 or more arguments
     */
    @Override
    public void warn(final String format, final Object... arguments) {
        log.warn(format(format), arguments);
    }

    /**
     * Log a message at the WARN level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the WARN level.
     *
     * @param format the format string
     * @param arg1   the first argument
     * @param arg2   the second argument
     */
    @Override
    public void warn(final String format, final Object arg1, final Object arg2) {
        log.warn(format(format), arg1, arg2);
    }

    /**
     * Log an exception (throwable) at the WARN level with an
     * accompanying message.
     *
     * @param msg       the message accompanying the exception
     * @param throwable the exception (throwable) to log
     */
    @Override
    public void warn(final String msg, final Throwable throwable) {
        log.warn(format(msg), throwable);
    }

    /**
     * Log a message at the ERROR level.
     *
     * @param msg the message string to be logged
     */
    @Override
    public void error(final String msg) {
        log.error(format(msg));
    }

    /**
     * Log a message at the ERROR level according to the specified format
     * and argument.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the ERROR level.
     *
     * @param format the format string
     * @param arg    the argument
     */
    @Override
    public void error(final String format, final Object arg) {
        log.error(format(format), arg);
    }

    /**
     * Log a message at the ERROR level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous object creation when the logger
     * is disabled for the ERROR level.
     *
     * @param format the format string
     * @param arg1   the first argument
     * @param arg2   the second argument
     */
    @Override
    public void error(final String format, final Object arg1, final Object arg2) {
        log.error(format(format), arg1, arg2);
    }

    /**
     * Log a message at the ERROR level according to the specified format
     * and arguments.
     *
     * <p>This form avoids superfluous string concatenation when the logger
     * is disabled for the ERROR level. However, this variant incurs the hidden
     * (and relatively small) cost of creating an <code>Object[]</code> before invoking the method,
     * even if this logger is disabled for ERROR. The variants taking
     * {@link #error(String, Object) one} and {@link #error(String, Object, Object) two}
     * arguments exist solely in order to avoid this hidden cost.
     *
     * @param format    the format string
     * @param arguments a list of 3 or more arguments
     */
    @Override
    public void error(final String format, final Object... arguments) {
        log.error(format(format), arguments);
    }

    /**
     * Log an exception (throwable) at the ERROR level with an
     * accompanying message.
     *
     * @param msg       the message accompanying the exception
     * @param throwable the exception (throwable) to log
     */
    @Override
    public void error(final String msg, final Throwable throwable) {
        log.error(format(msg), throwable);
    }

}
