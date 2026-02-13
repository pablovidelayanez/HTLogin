import logging
import sys
from typing import Optional
from .colors import Colors

logger: Optional[logging.Logger] = None


class ColoredFormatter(logging.Formatter):
    
    COLORS = {
        'DEBUG': Colors.DIM + Colors.WHITE,
        'INFO': Colors.BRIGHT_CYAN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.BRIGHT_RED + Colors.BOLD,
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Colors.RESET}"
        
        original_msg = record.getMessage()
        if 'Testing' in original_msg:
            colored_msg = original_msg.replace('Testing', f'{Colors.BRIGHT_BLUE}Testing{Colors.RESET}')
            record.msg = colored_msg
            record.args = ()
        elif record.levelname.startswith('INFO'):
            pass
        
        return super().format(record)


def get_logger() -> logging.Logger:
    global logger
    if logger is None:
        logger = logging.getLogger('HTLogin')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(ColoredFormatter('%(levelname)s: %(message)s'))
            logger.addHandler(handler)
    return logger


def setup_logging(log_file: Optional[str] = None, verbose: bool = False) -> logging.Logger:
    global logger
    
    logger = logging.getLogger('HTLogin')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    logger.handlers = []
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = ColoredFormatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger
