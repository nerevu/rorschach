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


class AWS(Resource):
    def __init__(self, resource, **kwargs):
        rid = kwargs.get("rid", "nerevu")

        try:
            session = boto3.Session(profile_name=rid)
        except ProfileNotFound:
            # passed in from app.config
            keys = {"aws_access_key_id", "aws_secret_access_key", "region_name"}
            boto_kwargs = {k: v for k, v in kwargs.items() if k in keys}
            session = boto3.Session(**boto_kwargs)

        self.session = session
        super().__init__(__name__, resource, **kwargs)


class Cloudfront(AWS):
    def __init__(self, **kwargs):
        super().__init__("cloudfront", **kwargs)
        self.client = self.session.client(self.resource)


class Distribution(Cloudfront):
    items = [
        "/icons/*.svg",
        "/images*",
        "/favicon.*",
        "/*.json",
    ]

    def __init__(self, distribution_id=None, **kwargs):
        kwargs.update(
            {
                "id_field": "distribution_id",
                "sub_resource": "distribution",
                "subresource_id": distribution_id,
            }
        )

        super().__init__(**kwargs)

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/
    # cloudfront.html#CloudFront.Client.create_invalidation
    def invalidate(self, *args, **kwargs):
        return self.client.create_invalidation(
            DistributionId=self.id,
            InvalidationBatch={
                "Paths": {"Quantity": 4, "Items": self.items},
                "CallerReference": dt.utcnow().isoformat(),
            },
        )


class DistributionHook(Webhook, Distribution):
    def __init__(self, **kwargs):
        methods = {"update": self.invalidate}
        kwargs.update(**self.kwargs)
        super().__init__(methods=methods, **kwargs)

    def process_value(self, value):
        method = self.METHODS.get(value)
        response = {"message": "Invalid action", "status_code": 400, "ok": False}
        return method(value) if method else response
