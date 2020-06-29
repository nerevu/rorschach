# -*- coding: utf-8 -*-
"""
    app.mappings
    ~~~~~~~~~~~~

    Timely / Xero mappings
"""
REUBEN_TIMELY = 933370
ADITYA_TIMELY = 1281455
MITCHELL_TIMELY = 1281876
MITCHELL_GSHEETS = "mitchell"
AUSTIN_GSHEETS = "austin"
LEVEL_1 = [AUSTIN_GSHEETS]
LEVEL_2 = [ADITYA_TIMELY, MITCHELL_TIMELY, MITCHELL_GSHEETS]
LEVEL_3 = []
LEVEL_4 = []
LEVEL_5 = [REUBEN_TIMELY]
TEAM = LEVEL_1 + LEVEL_2 + LEVEL_3 + LEVEL_4 + LEVEL_5

USERS = {
    REUBEN_TIMELY: LEVEL_5,
    ADITYA_TIMELY: LEVEL_2,
    MITCHELL_TIMELY: LEVEL_2,
    MITCHELL_GSHEETS: LEVEL_2,
    AUSTIN_GSHEETS: LEVEL_1,
}

POSITIONS = {
    "Creative Director": LEVEL_5,
    "Technical Director": LEVEL_5,
    "Partner": LEVEL_5,
    "Principal Developer": LEVEL_4,
    "Senior Designer": LEVEL_3,
    "Senior Consultant": LEVEL_3,
    "Senior Developer": LEVEL_3,
    "Consultant": LEVEL_2,
    "Developer": LEVEL_2,
    "Junior Developer": LEVEL_1,
    "Pro-Bono": TEAM,
    "Non-Billable": TEAM,
}

NAMES = {
    "Admin": ["1 Hour Internal Work"],
    "Consulting": ["1 Hour Consulting"],
    "Design": ["1 Hour Design", "1 Hour Internal Work"],
    "Development": ["1 Hour Development", "1 Hour R&D", "1 Hour Internal Work"],
    "Evaluating": ["1 Hour Internal Work"],
    "Finance": ["1 Hour Internal Work"],
    "Finance & Accounting": ["1 Hour Internal Work"],
    "HR": ["1 Hour Internal Work"],
    "Coaching": ["1 Hour Coaching"],
    "Training": ["1 Hour Coaching"],
    "Instructing": ["1 Hour Internal Work"],
    "Learning": ["1 Hour Client Work", "1 Hour Internal Work"],
    "Maintenance": ["1 Hour Development", "1 Hour R&D", "1 Hour Internal Work"],
    "Market": ["1 Hour Internal Work"],
    "Marketing": ["1 Hour Internal Work"],
    "Marketing/PR": ["1 Hour Internal Work"],
    "Misc": ["1 Hour Internal Work"],
    "Networking": ["1 Hour Internal Work"],
    "R&D": ["1 Hour R&D"],
    "Research": ["1 Hour Research", "1 Hour R&D"],
    "Sales": ["1 Hour Internal Work"],
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
