# -*- coding: utf-8 -*-
"""
    app.mappings
    ~~~~~~~~~~~~

    Timely / Xero mappings
"""
from json import load, dumps
from pathlib import Path

MAPPINGS_DIR = Path("app/mappings")
projects_p = MAPPINGS_DIR.joinpath("projects.json")
users_p = MAPPINGS_DIR.joinpath("users.json")
tasks_p = MAPPINGS_DIR.joinpath("tasks.json")

projects = load(projects_p.open())
users = load(users_p.open())
tasks = load(tasks_p.open())


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


def gen_proj_tasks(project_mapping, users, *args):
    for key, value in project_mapping.items():
        for user in users:
            kwargs = {"proj_pair": {key, value}, "user": user}
            proj_tasks = dict(task_mapper(tasks, *args, **kwargs))

            if proj_tasks:
                yield (key, user, proj_tasks)


settings = [("projects", projects), ("users", users)]

timely_to_xero = {
    map_name: dict(reg_mapper(mapping, "timely", "xero"))
    for map_name, mapping in settings
}

xero_to_timely = {
    map_name: dict(reg_mapper(mapping, "xero", "timely"))
    for map_name, mapping in settings
}

args = (timely_to_xero["projects"], timely_to_xero["users"].keys(), "timely", "xero")
results = gen_proj_tasks(*args)
timely_to_xero["tasks"] = {(key, user): proj_tasks for key, user, proj_tasks in results}
