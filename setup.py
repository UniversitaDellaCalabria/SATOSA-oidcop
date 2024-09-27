from glob import glob
from setuptools import setup


def readme():
    with open("README.md") as f:
        return f.read()


_pkg_name = "satosa_oidcop"

setup(
    name=_pkg_name,
    description="SATOSA Frontend based on idetity python oidcop",
    long_description=readme(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    url="https://github.com/UniversitaDellaCalabria/satosa-oidcop",
    author="Giuseppe De Marco",
    author_email="giuseppe.demarco@unical.it",
    license="License :: OSI Approved :: GNU Affero General Public License v3",
    packages=[f"{_pkg_name}"],
    package_dir={f"{_pkg_name}": f"{_pkg_name}"},
    package_data={
        f"{_pkg_name}": [
            i.replace(f"{_pkg_name}/", "")
            for i in glob(f"{_pkg_name}/**", recursive=True)
        ]
    },
    install_requires=[
        "satosa>=8.0.0",
        "pymongo>=3.11,<5.0",
        "idpyoidc>=4.1.0,<4.2.0",
    ],
)
