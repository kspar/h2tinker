from h2tinker import log


def assert_error(condition: bool, msg: str, *msg_args):
    assert condition, msg.format(*msg_args)


def assert_warn(condition: bool, msg: str, *msg_args):
    if not condition:
        log.warn(msg.format(*msg_args))
