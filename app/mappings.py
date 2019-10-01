# -*- coding: utf-8 -*-
"""
    app.mappings
    ~~~~~~~~~~~~

    Timely / Xero mappings
"""
projects = [
    {"timely": 2960359, "xero": "15ff819d-6d69-406c-98c5-ed9ab9163779"},
    {"timely": 2906218},
    {"timely": 2906240},
    {"timely": 2954285, "xero": "b1d797e3-e54b-4686-b83f-d8ea5a35f1c2"},
    {"timely": 2389295, "xero": "803591c3-72af-4475-888f-7c4c50044589"},
    {"timely": 2906311, "xero": "615c8090-938d-4ee7-8f4e-6ae945920507"},
    {"timely": 2906312},
    {"timely": 2973544},
    {"timely": 2980115},
    {"timely": 2954247},
    {"timely": 2973418},
    {"timely": 2973485},
    {"timely": 2906239},
    {"timely": 2973420, "xero": "23be1505-900b-4504-b1fe-cf1b1c7e1d12"},
    {"timely": 2973417, "xero": "3fe4d0ef-b45f-4812-8ca8-9c64f6bd679c"},
    {"timely": 2906308},
]

users = [
    {"timely": 933370, "xero": "a76380db-eb5f-4fe4-8975-99ad2fabbd13"},
    {"timely": 1281455, "xero": "3f7626f2-5064-4499-a96c-e73653e5aa01"},
    {"timely": 1281876, "xero": "b21daba7-83b1-4a94-8467-35bb1964abd0"},
]

tasks = [
    {
        "timely": {"task": 1344431, "project": 2389295},
        "xero": {
            "task": "ef251547-9e8a-4304-8a4b-ac6b4bd631e4",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344444, "project": 2389295},
        "xero": {
            "task": "9f34793b-56ec-4b09-a07e-6b99e0fec2f3",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344445, "project": 2389295},
        "xero": {
            "task": "f73a0a0d-92ca-4981-8008-44e9bc3cda9b",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1339639, "project": 2389295},
        "xero": {
            "task": "1bee78cf-3b74-460a-8e6a-d957276d7177",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344464, "project": 2389295},
        "xero": {
            "task": "1bee78cf-3b74-460a-8e6a-d957276d7177",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1340560, "project": 2389295},
        "xero": {
            "task": "1bee78cf-3b74-460a-8e6a-d957276d7177",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1339636, "project": 2389295},
        "xero": {
            "task": "001313ee-c233-436e-9d29-ec6d46eaaa0e",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344449, "project": 2389295},
        "xero": {
            "task": "803591c3-72af-4475-888f-7c4c50044589",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
]


def reg_mapper(mapping, *args):
    for pair in mapping:
        if all(map(pair.get, args)):
            yield tuple(map(pair.get, args))


def task_mapper(mapping, *args, proj_pair=None):
    for task_pair in mapping:
        if {task_pair.get(arg, {}).get("project") for arg in args} == proj_pair:
            yield tuple(task_pair[arg]["task"] for arg in args)


def gen_proj_tasks(project_mapping, *args):
    for key, value in project_mapping.items():
        proj_tasks = dict(task_mapper(tasks, *args, proj_pair={key, value}))

        if proj_tasks:
            yield (key, proj_tasks)


settings = [("projects", projects), ("users", users)]

timely_to_xero = {
    map_name: dict(reg_mapper(mapping, "timely", "xero"))
    for map_name, mapping in settings
}

xero_to_timely = {
    map_name: dict(reg_mapper(mapping, "xero", "timely"))
    for map_name, mapping in settings
}

timely_to_xero["tasks"] = dict(
    gen_proj_tasks(timely_to_xero["projects"], "timely", "xero")
)

xero_to_timely["tasks"] = dict(
    gen_proj_tasks(xero_to_timely["projects"], "xero", "timely")
)
