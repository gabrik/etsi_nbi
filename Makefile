.PHONY: all test clean

SHELL := /bin/bash

BRANCH ?= master

all:
	$(MAKE) clean_build build
	$(MAKE) clean_build package

clean: clean_build
	rm -rf .build

clean_build:
	rm -rf build
	find osm_nbi -name '*.pyc' -delete
	find osm_nbi -name '*.pyo' -delete

prepare:
	mkdir -p build/
	cp tox.ini build/
	cp MANIFEST.in build/
	cp requirements.txt build/
	cp README.rst build/
	cp setup.py build/
	cp stdeb.cfg build/
	cp -r osm_nbi build/
	cp LICENSE build/osm_nbi


package: prepare
#	apt-get install -y python-stdeb
	cd build && python3 setup.py --command-packages=stdeb.command sdist_dsc  # --with-python2=False
	cd build/deb_dist/osm-nbi-* && dpkg-buildpackage -rfakeroot -uc -us
	mkdir -p .build
	cp build/deb_dist/python3-*.deb .build/

snap:
	echo "Nothing to be done yet"

install: package
	dpkg -i .build/python-osm-nbi*.deb
	cd .. && \
	OSMLIBOVIM_PATH=`python -c 'import lib_osm_openvim; print lib_osm_openvim.__path__[0]'` || FATAL "lib-osm-openvim was not properly installed" && \
	OSMNBI_PATH=`python3 -c 'import osm_nbi; print(osm_nbi.__path__[0])'` || FATAL "osm-nbi was not properly installed" && \
	service osm-nbi restart

develop: prepare
#	pip install -r requirements.txt
	cd build && ./setup.py develop

test:
	echo "TODO"

