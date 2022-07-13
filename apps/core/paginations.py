from rest_framework import pagination
from rest_framework.response import Response


class MetaPagination(pagination.PageNumberPagination):
    meta = {"code": 200, "message": "success"}

    def get_paginated_response(self, data):
        return Response(
            {
                "meta": self.meta,
                "data": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                    "count": self.page.paginator.count,
                    "results": data,
                },
            }
        )
