import os
from pymisp import PyMISP


class MISPClient:
    def __init__(self):
        api_key = os.environ.get("MISP_API_KEY")

        if not api_key:
            raise RuntimeError("MISP_API_KEY is not set")

        self.misp = PyMISP(
            "http://127.0.0.1",
            api_key,
            ssl=False,
            timeout=10
        )

    def lookup_ioc(self, ioc):
        results = self.misp.search(
            "attributes",
            value=ioc,
            pythonify=True
        )

        return [
            {
                "value": attribute.value,
                "type": attribute.type,
                "category": attribute.category,
                "comment": attribute.comment,
                "event_id": attribute.event_id
            }
            for attribute in results
        ]
