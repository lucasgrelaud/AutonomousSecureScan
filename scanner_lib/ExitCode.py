from enum import Enum


class ExitCode(Enum):
    NORMAL = 0
    BAD_TARGET_NETWORK = 1
    BAD_EXCLUDED_IP = 2
    NETWORKING_ERROR = 3
    NON_ROOT_LAUNCH = 4
    TAR_ERROR = 5