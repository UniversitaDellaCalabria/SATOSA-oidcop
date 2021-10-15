import re

from glob import glob
from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

_pkg_name = 'satosa_oidcop'

with open(f'{_pkg_name}/__init__.py', 'r') as fd:
    VERSION = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name=_pkg_name,
    version=VERSION,
    description="SATOSA Frontend based on idetity python oidcop",
    long_description=readme(),
    long_description_content_type='text/markdown',
    classifiers=['Development Status :: 5 - Production/Stable',
                 'License :: OSI Approved :: GNU Affero General Public License v3',
                 'Programming Language :: Python :: 3'],
    url='https://github.com/UniversitaDellaCalabria/satosa-oidcop',
    author='Giuseppe De Marco',
    author_email='giuseppe.demarco@unical.it',
    license='License :: OSI Approved :: GNU Affero General Public License v3',
    packages=[f"{_pkg_name}"],
    package_dir={f"{_pkg_name}": f"{_pkg_name}"},
    package_data={f"{_pkg_name}": [
            i.replace(f'{_pkg_name}/', '')
            for i in glob(f'{_pkg_name}/**', recursive=True)
        ]
    },
    install_requires=[
        "satosa>=7.0.3",
        "pymongo >= 3.11",
        "oidcop == 2.2.0"
    ],
)
