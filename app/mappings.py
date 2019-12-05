# -*- coding: utf-8 -*-
"""
    app.mappings
    ~~~~~~~~~~~~

    Timely / Xero mappings
"""
from json import load, dumps
from pathlib import Path

REUBEN = 933370
ADITYA = 1281455
MITCHELL = 1281876
CONSULTANTS = [ADITYA, MITCHELL]
TEAM = [REUBEN] + CONSULTANTS

USERS = {REUBEN: [REUBEN], ADITYA: CONSULTANTS, MITCHELL: CONSULTANTS}

MAPPINGS_DIR = Path("app/mappings")
tasks_p = MAPPINGS_DIR.joinpath("tasks.json")


def reg_mapper(mapping, *args):
    for pair in mapping:
        if all(map(pair.get, args)):
            yield tuple(map(pair.get, args))


def task_mapper(mapping, *args, proj_pair=None, user=None):
    for task_pair in mapping:
        projects = {task_pair.get(arg, {}).get("project") for arg in args}
        project_match = projects == proj_pair

        # Timely tasks apply to all users whereas Xero tasks are user specific
        # only implementing Timely -> Xero for now
        users = task_pair.get(args[0], {}).get("users")
        user_match = user in users

        if project_match and user_match:
            yield tuple(task_pair[arg]["task"] for arg in args)


def gen_task_mapping(project_mapping, users, *args):
    tasks = load(tasks_p.open())

    for key, value in project_mapping.items():
        for user in users:
            kwargs = {"proj_pair": {key, value}, "user": user}
            proj_tasks = dict(task_mapper(tasks, *args, **kwargs))

            if proj_tasks:
                yield (key, user, proj_tasks)
