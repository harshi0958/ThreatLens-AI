import logging

from backend.app.core.config import LOG_LEVEL

logger = logging.getLogger('threatlens')
logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(handler)
