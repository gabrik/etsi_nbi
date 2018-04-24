#!/usr/bin/env python3

import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
_name = "osm_nbi"
VERSION = "0.1.3" 
README = open(os.path.join(here, 'README.rst')).read()

setup(
    name=_name,
    description='OSM North Bound Interface',
    long_description=README,
    # version_command=('git describe --tags --long --dirty', 'pep440-git'),
    version=VERSION,
    python_requires='>3.5.0',
    author='ETSI OSM',
    author_email='alfonso.tiernosepulveda@telefonica.com',
    maintainer='Alfonso Tierno',
    maintainer_email='alfonso.tiernosepulveda@telefonica.com',
    url='https://osm.etsi.org/gitweb/?p=osm/NBI.git;a=summary',
    license='Apache 2.0',

    packages=[_name],
    include_package_data=True,
    data_files=[('/etc/osm/', ['osm_nbi/nbi.cfg']),
                ('/etc/systemd/system/', ['osm_nbi/osm-nbi.service']),
                ],

    install_requires=[
        'CherryPy', 'pymongo', 'jsonschema'
        # 'PyYAML',
    ],
    # setup_requires=['setuptools-version-command'],
    # test_suite='nose.collector',
    # entry_points='''
    #     [console_scripts]
    #     osm=osm_nbi.nbi:nbi
    #     ''',
)

