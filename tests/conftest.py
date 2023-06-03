import logging
import pymongo
import pytest

logger = logging.getLogger(__name__)

from satosa.context import Context
from satosa.state import State


@pytest.fixture
def context():
    context = Context()
    context.state = State()
    return context


import atexit
import random
import shutil
import subprocess
import tempfile
import time

import pymongo
import pytest


class DummyInterface:
    
    def wait(self):
        return True
    
    def terminate(self):
        return True


class MongoTemporaryInstance(object):
    """Singleton to manage a temporary MongoDB instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            atexit.register(cls._instance.shutdown)
        return cls._instance

    def __init__(self):
        self._tmpdir = tempfile.mkdtemp()
        self._port = 27017
        
        try:
            self._process = subprocess.Popen(
                [
                    'mongod', '--bind_ip', 'localhost',
                    '--port', str(self._port),
                    '--dbpath', self._tmpdir,
                    '--nojournal',
                    '--noauth',
                    '--syncdelay', '0'
                ],
                stdout=open('/tmp/mongo-temp.log', 'wb'),
                stderr=subprocess.STDOUT
            )
        except FileNotFoundError as e:
            logger.warning(
                "Mongodb executable not found to start test MongoDB instance, "
                f"trying to connect to docker mongodb: {e}"
            )
            self._process = DummyInterface()

        # XXX: wait for the instance to be ready
        #      Mongo is ready in a glance, we just wait to be able to open a
        #      Connection.
        for i in range(10):
            time.sleep(0.2)
            try:
                self._conn = pymongo.MongoClient('localhost', self._port)
            except pymongo.errors.ConnectionFailure:
                continue
            else:
                break
        else:
            self.shutdown()
            assert False, 'Cannot connect to the mongodb test instance'

    @property
    def conn(self):
        return self._conn

    @property
    def port(self):
        return self._port

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    def get_uri(self):
        """
        Convenience function to get a mongodb URI to the temporary database.

        :return: URI
        """
        return 'mongodb://localhost:{port!s}'.format(port=self.port)


@pytest.fixture
def mongodb_instance():
    tmp_db = MongoTemporaryInstance()
    yield tmp_db
    tmp_db.shutdown()
