
# osm-nbi

osm-nbi is the North Bound Interface for OSM, REST client serving json/yaml
It follows ETSI SOL005 recomendations


#### Updated version with Eclipse fog05 support : vim_type fos for RELEASE FOUR

## How to build the image

You need docker in order to build che docker image for the RO

	$ cd ~
  	$ git clone https://github.com/gabrik/etsi_nbi
  	$ git -C etsi_nbi checkout v4-city
  	$ sg docker -c "docker build ~/etsi_nbi  -f ~/etsi_nbi/Dockerfile.local -t dockercity/nbi --no-cache"


Then if you have a running OSM installation on docker you have to edit the
file `/etc/osm/docker/docker-compose.yaml` and update the image for the NBI

	nbi:
   	  image: dockercity/nbi


