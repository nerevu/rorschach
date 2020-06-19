# -*- coding: utf-8 -*-
"""
    app.mappings
    ~~~~~~~~~~~~

    Timely / Xero mappings
"""
REUBEN = 933370
ADITYA = 1281455
MITCHELL = 1281876
CONSULTANTS = [ADITYA, MITCHELL]
TEAM = [REUBEN] + CONSULTANTS

USERS = {REUBEN: [REUBEN], ADITYA: CONSULTANTS, MITCHELL: CONSULTANTS}


def reg_mapper(mapping, *args):
    for pair in mapping:
        if all(map(pair.get, args)):
            yield tuple(map(pair.get, args))


def task_mapper(mapping, *args, proj_pair=None, user=None):
    for pair in mapping:
        projects = {pair.get(arg, {}).get("project") for arg in args}
        project_match = projects == proj_pair

        # Timely tasks apply to all users whereas Xero tasks are user specific
        # only implementing Timely -> Xero for now
        users = pair.get(args[0], {}).get("users")

        if project_match and user in users:
            yield tuple(pair[arg]["task"] for arg in args)


def gen_task_mapping(mapping, *args, user_mappings=None, project_mappings=None):
    for key, value in project_mappings.items():
        for user in user_mappings:
            kwargs = {"proj_pair": {key, value}, "user": user}
            proj_tasks = dict(task_mapper(mapping, *args, **kwargs))

            if proj_tasks:
                yield [(key, user), proj_tasks]
