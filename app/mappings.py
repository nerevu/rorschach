# -*- coding: utf-8 -*-
"""
    app.mappings
    ~~~~~~~~~~~~

    Timely / Xero mappings
"""
REUBEN_TIMELY = 933370
ADITYA_TIMELY = 1281455
MITCHELL_TIMELY = 1281876
MALLORY_TIMELY = 2014908
TIFFANY_TIMELY = 2014349
MITCHELL_GSHEETS = "mitchell"
AUSTIN_GSHEETS = "austin"
AUSTIN_AIRTABLE = "alice-seaborn"

LEVEL_1 = [AUSTIN_GSHEETS, AUSTIN_AIRTABLE]
LEVEL_2 = [ADITYA_TIMELY, MITCHELL_TIMELY, MITCHELL_GSHEETS, TIFFANY_TIMELY]
LEVEL_3 = [MALLORY_TIMELY]
LEVEL_4 = []
LEVEL_5 = [REUBEN_TIMELY]
TEAM = LEVEL_1 + LEVEL_2 + LEVEL_3 + LEVEL_4 + LEVEL_5

USERS = {
    REUBEN_TIMELY: LEVEL_5,
    ADITYA_TIMELY: LEVEL_2,
    MITCHELL_TIMELY: LEVEL_2,
    MALLORY_TIMELY: LEVEL_3,
    TIFFANY_TIMELY: LEVEL_2,
    MITCHELL_GSHEETS: LEVEL_2,
    AUSTIN_GSHEETS: LEVEL_1,
    AUSTIN_AIRTABLE: LEVEL_1,
}

POSITIONS = {
    "creative director": LEVEL_5,
    "technical director": LEVEL_5,
    "partner": LEVEL_5,
    "principal developer": LEVEL_4,
    "senior designer": LEVEL_3,
    "senior consultant": LEVEL_3,
    "senior developer": LEVEL_3,
    "consultant": LEVEL_2,
    "developer": LEVEL_2,
    "junior developer": LEVEL_1,
    "junior consultant": LEVEL_1,
    "pro-bono": TEAM,
    "non-billable": TEAM,
}


def reg_mapper(mapping, *args):
    for pair in mapping:
        if all(map(pair.get, args)):
            yield tuple(map(pair.get, args))


def task_mapper(mapping, *args, proj_pair=None, user=None):
    for pair in mapping:
        projects = {pair.get(arg, {}).get("project") for arg in args}
        project_match = projects == proj_pair

        # Xero tasks are user and project specific.
        # Only converting to Xero for now (not from Xero).
        users = set(pair.get(args[0], {}).get("users", []))

        if project_match and user in users:
            yield tuple(pair[arg]["task"] for arg in args)


def gen_task_mapping(mapping, *args, user_mappings=None, project_mappings=None):
    for projects in project_mappings:
        proj0, proj1 = map(projects.get, args)

        if proj0 is None or proj1 is None:
            continue

        for users in user_mappings:
            user = users.get(args[0])

            if not user:
                continue

            kwargs = {"proj_pair": {proj0, proj1}, "user": user}

            for task_ids in task_mapper(mapping, *args, **kwargs):
                # [(timely-proj-id, timely-user-id, timely-task-id), xero-task-id]
                yield [(proj0, user, task_ids[0]), task_ids[1]]
