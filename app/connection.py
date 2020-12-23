# -*- coding: utf-8 -*-
"""
    app.connection
    ~~~~~~~~~~~~~~

    Provides the redis connection
"""
import redis
import pygogo as gogo

from config import Config

logger = gogo.Gogo(__name__, monolog=True).logger

try:
    conn = redis.from_url(Config.RQ_DASHBOARD_REDIS_URL)
except Exception as err:
    logger.error(err)
    conn = None
