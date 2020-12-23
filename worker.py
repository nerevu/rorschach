# -*- coding: utf-8 -*-
"""
    app.worker
    ~~~~~~~~~~

    Provides the rq worker
"""
from rq import Worker, Queue, Connection
from rq.registry import FailedJobRegistry
from app.connection import conn

import pygogo as gogo

DEF_LISTEN = ["high", "default", "low"]

logger = gogo.Gogo(__name__).logger


def initialize(listen=None):
    if conn:
        listen = listen or DEF_LISTEN

        with Connection(conn):
            queues = [Queue(priority) for priority in listen]
            registries = [FailedJobRegistry(queue=queue) for queue in queues]
            num_jobs = sum(registry.get_job_ids() for registry in registries)

            if num_jobs:
                logger.warning(f"{num_jobs} failed jobs in queue!")

            worker = Worker(queues)
            worker.work()
    else:
        logger.error("Redis connection not found!")


if __name__ == "__main__":
    initialize()
