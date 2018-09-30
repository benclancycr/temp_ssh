#!/usr/bin/env python

from setuptools import setup
from temp_ssh import __version__

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

install_requirements = [
        "boto3>=1.3.0,<2",
        "setuptools==37.0.0",
        "six==1.11.0",
        "wheel==0.30.0"
        ]

setup(
    name="temp_ssh",
    version=__version__,
    description="Temporary SSH Tool",
    long_description=readme,
    author="Ben Clancy",
    author_email="me@benclancy.com",
    license='Apache2',
    url="https://github.com/benclancycr/temp_ssh",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Environment :: Console",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7"
    ],
    install_requires=install_requirements,
)
