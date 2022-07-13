class ResponseObject:
    meta: dict
    data: dict or None

    def __init__(self) -> dict or None:
        self.meta = {"code": 200, "message": "success"}
        self.data = None

    def set_not_found_resp(self, message: str = "Data not found!"):
        self.meta = {"code": 404, "message": message}
        self.data = None
