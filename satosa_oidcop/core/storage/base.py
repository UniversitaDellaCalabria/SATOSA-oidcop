from typing import Optional


class Storage(object):
    def fetch(self, information_type:str, key: Optional[str]):
        raise NotImplementedError()

    def store(self, information_type:str, value, key=Optional[str]):
        raise NotImplementedError()