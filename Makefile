
clean:
	rm -rf dist deb_dist .build osm_nbi-*.tar.gz osm_nbi.egg-info eggs

package:
	python3 setup.py --command-packages=stdeb.command sdist_dsc
	cp python3-osm-nbi.postinst deb_dist/osm-nbi*/debian
	cd deb_dist/osm-nbi*/debian && echo "osm-common python3-osm-common" > py3dist-overrides
	# cd deb_dist/osm-nbi*/debian && echo "pip3 python3-pip"       >> py3dist-overrides
	cd deb_dist/osm-nbi*/  && dpkg-buildpackage -rfakeroot -uc -us
	mkdir -p .build
	cp deb_dist/python3-osm-nbi*.deb .build/


