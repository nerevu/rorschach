# -*- coding: utf-8 -*-
"""
    app.providers.aws
    ~~~~~~~~~~~~~~~~~

    Provides AWS API related functions
"""
from datetime import datetime as dt

import boto3

from botocore.exceptions import ProfileNotFound

from app.routes.webhook import Webhook
from app.routes.auth import Resource

PREFIX = __name__.split(".")[-1]


class AWS(Resource):
    def __init__(self, *args, **kwargs):
        rid = kwargs.get("rid", "nerevu")

        try:
            session = boto3.Session(profile_name=rid)
        except ProfileNotFound:
            # passed in from app.config
            keys = {"aws_access_key_id", "aws_secret_access_key", "region_name"}
            boto_kwargs = {k: v for k, v in kwargs.items() if k in keys}
            session = boto3.Session(**boto_kwargs)

        self.session = session
        super().__init__(PREFIX, *args, **kwargs)


class Cloudfront(AWS):
    def __init__(self, *args, **kwargs):
        super().__init__("cloudfront", *args, **kwargs)
        self.client = self.session.client(self.resource)


class Distribution(Cloudfront):
    items = [
        "/icons/*.svg",
        "/images*",
        "/favicon.*",
        "/*.json",
    ]

    def __init__(self, *args, distribution_id=None, **kwargs):
        def_distribution_id = self.kwargs.get("cloudfront_distribution_id")

        kwargs.update(
            {
                "id_field": "distribution_id",
                "sub_resource": "distribution",
                "subresource_id": distribution_id or def_distribution_id,
            }
        )

        super().__init__(*args, **kwargs)

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/
    # cloudfront.html#CloudFront.Client.create_invalidation
    def invalidate(self, **kwargs):
        return self.client.create_invalidation(
            DistributionId=self.id,
            InvalidationBatch={
                "Paths": {"Quantity": 4, "Items": self.items},
                "CallerReference": dt.utcnow().isoformat(),
            },
        )


class Hooks(Webhook):
    def __init__(self, *args, **kwargs):
        super().__init__(PREFIX, *args, **kwargs)

    def process_value(self, value):
        method = self.METHODS.get(value)
        return method(value) if method else {}
