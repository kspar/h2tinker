import time
import enum


class LogLevel(enum.IntEnum):
    DEBUG = 400
    INFO = 300
    WARN = 200
    NONE = 100


GLOBAL_LOG_LEVEL = LogLevel.INFO


def set_global_log_level(log_level: LogLevel):
    global GLOBAL_LOG_LEVEL
    GLOBAL_LOG_LEVEL = log_level


def _print_timed_formatted_msg(msg: str, *msg_args: object):
    formatted_msg = msg.format(*msg_args)
    print('{} {}'.format(round(time.time(), 5), formatted_msg))


def warn(msg: object, *msg_args: object):
    if GLOBAL_LOG_LEVEL >= LogLevel.WARN:
        _print_timed_formatted_msg('WARN :: ' + str(msg), *msg_args)


def info(msg: object, *msg_args: object):
    if GLOBAL_LOG_LEVEL >= LogLevel.INFO:
        _print_timed_formatted_msg('INFO :: ' + str(msg), *msg_args)


def debug(msg: object, *msg_args: object):
    if GLOBAL_LOG_LEVEL >= LogLevel.DEBUG:
        _print_timed_formatted_msg('DEBUG :: ' + str(msg), *msg_args)
