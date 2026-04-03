class SOCPlatformError(Exception):
    pass


class ExtractionError(SOCPlatformError):
    pass


class TransformationError(SOCPlatformError):
    pass


class LoadError(SOCPlatformError):
    pass


class ConfigurationError(SOCPlatformError):
    pass