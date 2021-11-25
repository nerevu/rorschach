# -*- coding: utf-8 -*-
"""
    app.connection
    ~~~~~~~~~~~~~~

    Provides the redis connection
"""
import redis
import pygogo as gogo

from config import Config

from app.helpers import flask_formatter as formatter

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger

try:
    conn = redis.from_url(Config.RQ_DASHBOARD_REDIS_URL)
except Exception as err:
    logger.warning(err)
    conn = None
