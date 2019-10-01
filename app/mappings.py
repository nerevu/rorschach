# -*- coding: utf-8 -*-
"""
    app.mappings
    ~~~~~~~~~~~~

    Timely / Xero mappings
"""
REUBEN = {933370}
CONSULTANTS = {1281455, 1281876}
TEAM = REUBEN | CONSULTANTS

projects = [
    {"timely": 2960359, "xero": "15ff819d-6d69-406c-98c5-ed9ab9163779"},
    {"timely": 2906218, "xero": "ba4c61a8-e189-4fd4-a113-fb2c67626bbd"},
    {"timely": 2906240, "xero": "f9d0e04b-f07c-423d-8975-418159180dab"},
    {"timely": 2954285, "xero": "b1d797e3-e54b-4686-b83f-d8ea5a35f1c2"},
    {"timely": 2389295, "xero": "803591c3-72af-4475-888f-7c4c50044589"},
    {"timely": 2906311, "xero": "615c8090-938d-4ee7-8f4e-6ae945920507"},
    {"timely": 2906312, "xero": "37b69d72-7168-47d4-8a9f-d225fccf8b38"},
    {"timely": 2973544, "xero": "2d4c9cd1-40b3-41ba-b584-1f84e1d88910"},
    {"timely": 2980115, "xero": "c74d4b92-4a5c-4301-80ac-a601593b41ba"},
    {"timely": 2954247, "xero": "c8b18830-fed0-4979-8c42-6619c4b6b67c"},
    {"timely": 2973418, "xero": "4ae942e8-af62-4318-b569-7476df14cbef"},
    {"timely": 2973485, "xero": "69cb6ef7-7886-4172-8112-bbc70e949a9e"},
    {"timely": 2906239, "xero": "7fe1e7c0-24e2-4c26-809f-654f1cbae1f1"},
    {"timely": 2973420, "xero": "23be1505-900b-4504-b1fe-cf1b1c7e1d12"},
    {"timely": 2973417, "xero": "3fe4d0ef-b45f-4812-8ca8-9c64f6bd679c"},
    {"timely": 2906308, "xero": "62859aaa-0b21-4a8c-9009-03f3458a9fe2"},
]

users = [
    {"timely": 933370, "xero": "a76380db-eb5f-4fe4-8975-99ad2fabbd13"},
    {"timely": 1281455, "xero": "3f7626f2-5064-4499-a96c-e73653e5aa01"},
    {"timely": 1281876, "xero": "b21daba7-83b1-4a94-8467-35bb1964abd0"},
]

tasks = [
    {
        "timely": {"task": 1344431, "project": 2389295, "users": REUBEN},
        "xero": {
            "task": "ef251547-9e8a-4304-8a4b-ac6b4bd631e4",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344444, "project": 2389295, "users": REUBEN},
        "xero": {
            "task": "9f34793b-56ec-4b09-a07e-6b99e0fec2f3",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344445, "project": 2389295, "users": REUBEN},
        "xero": {
            "task": "f73a0a0d-92ca-4981-8008-44e9bc3cda9b",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1339639, "project": 2389295, "users": TEAM},
        "xero": {
            "task": "1bee78cf-3b74-460a-8e6a-d957276d7177",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344464, "project": 2389295, "users": TEAM},
        "xero": {
            "task": "1bee78cf-3b74-460a-8e6a-d957276d7177",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1340560, "project": 2389295, "users": TEAM},
        "xero": {
            "task": "1bee78cf-3b74-460a-8e6a-d957276d7177",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1339636, "project": 2389295, "users": TEAM},
        "xero": {
            "task": "001313ee-c233-436e-9d29-ec6d46eaaa0e",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344449, "project": 2389295, "users": REUBEN},
        "xero": {
            "task": "5ba6e7ab-f1dc-4395-a188-f26e9e5f1812",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344449, "project": 2389295, "users": CONSULTANTS},
        "xero": {
            "task": "217bcc76-3558-4037-be9e-c71dc1a9d765",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1344431, "project": 2389295, "users": CONSULTANTS},
        "xero": {
            "task": "66a9506d-8c45-4cab-b97f-9b27bf53402d",
            "project": "803591c3-72af-4475-888f-7c4c50044589",
        },
    },
    {
        "timely": {"task": 1339639, "project": 2906240, "users": CONSULTANTS},
        "xero": {
            "task": "f9d0e04b-f07c-423d-8975-418159180dab",
            "project": "f9d0e04b-f07c-423d-8975-418159180dab",
        },
    },
    {
        "timely": {"task": 1344431, "project": 2906311, "users": REUBEN},
        "xero": {
            "task": "03c04504-ae82-4f6d-bb97-36b479299cd2",
            "project": "615c8090-938d-4ee7-8f4e-6ae945920507",
        },
    },
    {
        "timely": {"task": 1344464, "project": 2954247, "users": CONSULTANTS},
        "xero": {
            "task": "a7f44e15-6a83-40fd-830b-1bcb0402861f",
            "project": "c8b18830-fed0-4979-8c42-6619c4b6b67c",
        },
    },
    {
        "timely": {"task": 1340560, "project": 2954285, "users": REUBEN},
        "xero": {
            "task": "53d25b8c-dbd0-4b25-b050-93e6094369c5",
            "project": "b1d797e3-e54b-4686-b83f-d8ea5a35f1c2",
        },
    },
    {
        "timely": {"task": 1339640, "project": 2960359, "users": REUBEN},
        "xero": {
            "task": "9387bff7-728b-4364-b89b-e8cc44758883",
            "project": "15ff819d-6d69-406c-98c5-ed9ab9163779",
        },
    },
    {
        "timely": {"task": 1339639, "project": 2973417, "users": REUBEN},
        "xero": {
            "task": "02f654be-1198-4358-9820-229661bade49",
            "project": "3fe4d0ef-b45f-4812-8ca8-9c64f6bd679c",
        },
    },
    {
        "timely": {"task": 1344431, "project": 2973418, "users": REUBEN},
        "xero": {
            "task": "c1b1fb50-94b4-4e65-bcd3-2c6bdcd24260",
            "project": "4ae942e8-af62-4318-b569-7476df14cbef",
        },
    },
    {
        "timely": {"task": 1339640, "project": 2973544, "users": REUBEN},
        "xero": {
            "task": "510a0d2d-f6e5-46eb-a3b0-bad77827e088",
            "project": "2d4c9cd1-40b3-41ba-b584-1f84e1d88910",
        },
    },
    # - Timely->Xero mapping for Mitchell Sotto:Instructing on Internal not found!
    {
        "timely": {"task": 1340560, "project": 2906240, "users": TEAM},
        "xero": {
            "task": "1219f749-ab38-4fb7-a302-e650448f9f18",
            "project": "f9d0e04b-f07c-423d-8975-418159180dab",
        },
    },
    # - Timely->Xero mapping for Reuben Cummings:HR on Internal not found!
    {
        "timely": {"task": 1344521, "project": 2906240, "users": REUBEN},
        "xero": {
            "task": "1219f749-ab38-4fb7-a302-e650448f9f18",
            "project": "f9d0e04b-f07c-423d-8975-418159180dab",
        },
    },
    # - Timely->Xero mapping for Reuben Cummings:Admin on Internal not found!
    {
        "timely": {"task": 1339639, "project": 2906240, "users": TEAM},
        "xero": {
            "task": "1219f749-ab38-4fb7-a302-e650448f9f18",
            "project": "f9d0e04b-f07c-423d-8975-418159180dab",
        },
    },
    # - Timely->Xero mapping for Reuben Cummings:Evaluating on Internal not found!
    {
        "timely": {"task": 1344451, "project": 2906240, "users": TEAM},
        "xero": {
            "task": "1219f749-ab38-4fb7-a302-e650448f9f18",
            "project": "f9d0e04b-f07c-423d-8975-418159180dab",
        },
    },
]


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
