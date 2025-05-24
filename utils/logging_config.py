"""
Logging configuration for the Network Configuration Parser.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    log_dir: str = "logs",
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    console_output: bool = True
):
    """
    Setup logging configuration for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Log file name (optional)
        log_dir: Directory for log files
        max_file_size: Maximum size of log file before rotation
        backup_count: Number of backup log files to keep
        console_output: Whether to output logs to console
    """
    
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        # Create log directory if it doesn't exist
        log_path = Path(log_dir)
        log_path.mkdir(exist_ok=True)
        
        log_file_path = log_path / log_file
        
        # Use rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file_path,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Set specific loggers to appropriate levels
    _configure_library_loggers()
    
    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured - Level: {level}, Console: {console_output}, File: {log_file}")


def _configure_library_loggers():
    """Configure logging levels for third-party libraries."""
    
    # Reduce verbosity of noisy libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('pandas').setLevel(logging.WARNING)
    logging.getLogger('xml').setLevel(logging.WARNING)
    logging.getLogger('lxml').setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_log_level(level: str):
    """
    Change the logging level for all handlers.
    
    Args:
        level: New logging level
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    for handler in root_logger.handlers:
        handler.setLevel(numeric_level)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Log level changed to: {level}")


def add_file_handler(log_file: str, level: str = "INFO", log_dir: str = "logs"):
    """
    Add a file handler to the root logger.
    
    Args:
        log_file: Log file name
        level: Logging level for this handler
        log_dir: Directory for log files
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create log directory if it doesn't exist
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    
    log_file_path = log_path / log_file
    
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create file handler
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file_path,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    
    # Add to root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Added file handler: {log_file_path}")


def setup_debug_logging():
    """Setup debug-level logging with detailed formatting."""
    
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s() - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler for debug
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    
    logger = logging.getLogger(__name__)
    logger.debug("Debug logging enabled")


class LoggerMixin:
    """Mixin class to add logging capability to any class."""
    
    @property
    def logger(self) -> logging.Logger:
        """Get logger for this class."""
        if not hasattr(self, '_logger'):
            self._logger = logging.getLogger(self.__class__.__module__ + '.' + self.__class__.__name__)
        return self._logger


def log_function_call(func):
    """Decorator to log function calls."""
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Function {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Function {func.__name__} failed with error: {e}")
            raise
    
    return wrapper


def log_performance(func):
    """Decorator to log function performance."""
    import time
    
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(func.__module__)
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"Function {func.__name__} completed in {duration:.3f} seconds")
            return result
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            logger.error(f"Function {func.__name__} failed after {duration:.3f} seconds with error: {e}")
            raise
    
    return wrapper 