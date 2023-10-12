from satosa.context import Context


class ExtendedContext(Context):  # pragma: no cover

    def __init__(self, **kwargs):
        super().__init__()
        self.http_headers = {}
        self.request_method = ""
        self.request_uri = ""
        self.request_authorization = ""
