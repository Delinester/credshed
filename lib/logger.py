#!/usr/bin/env python3

# by TheTechromancer

import atexit
import logging
from copy import copy
from pathlib import Path
from datetime import datetime
from multiprocessing import Queue
from logging.handlers import QueueHandler, QueueListener


### PRETTY COLORS ###

class ColoredFormatter(logging.Formatter):

    color_mapping = {
        'DEBUG':    69, # blue
        'INFO':     118, # green
        'WARNING':  208, # orange
        'ERROR':    196, # red
        'CRITICAL': 196, # red
    }

    char_mapping = {
        'DEBUG':    '*',
        'INFO':     '+',
        'WARNING':  '-',
        'ERROR':    '!',
        'CRITICAL': '!!!',
    }

    prefix = '\033[1;38;5;'
    suffix = '\033[0m'

    def __init__(self, pattern):

        super().__init__(pattern)


    def format(self, record):

        colored_record = copy(record)
        levelname = colored_record.levelname
        levelchar = self.char_mapping.get(levelname, '+')
        seq = self.color_mapping.get(levelname, 15) # default white
        colored_levelname = f'{self.prefix}{seq}m[{levelchar}]{self.suffix}'
        colored_record.levelname = colored_levelname

        return logging.Formatter.format(self, colored_record)



class CustomQueueListener(QueueListener):
    '''
    Ignore errors in the _monitor thread that result from a race condition when the program exits
    '''
    def _monitor(self):
        try:
            super()._monitor()
        except:
            pass



### LOG TO STDERR ###

console = logging.StreamHandler()
# tell the handler to use this format
console.setFormatter(ColoredFormatter('%(levelname)s %(message)s'))


### LOG TO FILE ###

root_logger = logging.getLogger('credshed')

# set up a multiprocessing queue to allow easy logging from subprocesses
log_queue = Queue()
listener = CustomQueueListener(log_queue, console)
log_sender = QueueHandler(log_queue)
root_logger.handlers = [log_sender]
#root_logger.handlers = [console]

# Log records are shipped through a multiprocessing.Queue so worker subprocesses can
# log to the same console.  That queue has a background "feeder" thread which, at
# interpreter shutdown, multiprocessing tries to join — and if the queue still holds
# unconsumed records (because nothing is draining it), that join BLOCKS FOREVER and
# the whole process hangs on exit.  Historically only the CLI started the listener,
# so any other user of the library (the web app, tools, tests, embedding code) left
# the queue undrained and hung at exit (long-running servers only escaped because the
# service manager eventually SIGKILLs them).  Start the listener once here so the
# queue is always drained, and guarantee a clean exit no matter how the library is
# used.
_listener_started = False


def start_listener():
    '''Start the logging queue listener exactly once (idempotent).'''
    global _listener_started
    if not _listener_started:
        try:
            listener.start()
            _listener_started = True
        except Exception:
            pass


def stop_listener():
    '''Stop the logging queue listener if running (idempotent).'''
    global _listener_started
    if _listener_started:
        try:
            listener.stop()
        except Exception:
            pass
        _listener_started = False


def _shutdown_logging():
    stop_listener()
    # Never let the queue's feeder thread block process exit (any records still
    # buffered here are console log lines, not data).
    try:
        log_queue.cancel_join_thread()
    except Exception:
        pass


start_listener()
atexit.register(_shutdown_logging)

logdir = Path('/var/log/credshed')
date_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
filename = f'credshed_{date_str}.log'
log_filename = str(logdir / filename)

# use logging to log logger logs
log = logging.getLogger('credshed.logger')

try:
    file_handler = logging.FileHandler(log_filename)
except (PermissionError, FileNotFoundError):
    fallback_logdir = Path.home() / '.credshed' / 'logs'
    fallback_logdir.mkdir(parents=True, exist_ok=True)
    log.debug(f'Unable to create log file at {logdir}, logging to {fallback_logdir}')
    file_handler = logging.FileHandler(fallback_logdir / filename)

log_format = '%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s'
file_handler.setFormatter(logging.Formatter(log_format))
root_logger.addHandler(file_handler)
root_logger.setLevel(logging.DEBUG)