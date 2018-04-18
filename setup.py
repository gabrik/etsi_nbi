#!/usr/bin/env python3

from setuptools import setup   #, find_packages

_name = "osm_nbi"

setup(
    name=_name,
    description='OSM North Bound Interface',
    # version_command=('git describe --tags --long --dirty', 'pep440-git'),
    version="0.1.0",
    author='ETSI OSM',
    author_email='alfonso.tiernosepulveda@telefonica.com',
    maintainer='Alfonso Tierno',
    maintainer_email='alfonso.tiernosepulveda@telefonica.com',
    url='https://osm.etsi.org/gitweb/?p=osm/NBI.git;a=summary',
    license='Apache 2.0',

    packages=[_name],   # find_packages(),
    include_package_data=True,
    data_files=[('/etc/osm/', ['osm_nbi/nbi.cfg']),
                ('/etc/systemd/system/', ['osm_nbi/osm-nbi.service']),
                ],

    install_requires=[
        'CherryPy', 'pymongo', 'jsonschema'
    ],
#    setup_requires=['setuptools-version-command'],
    # test_suite='nose.collector',
    # entry_points='''
    #     [console_scripts]
    #     osm=osm_nbi.nbi:nbi
    #     ''',
)
