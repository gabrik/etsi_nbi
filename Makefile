# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

OUT_DIR := osm_im
TREES_DIR := osm_im_trees
Q?=@

all: package
	$(MAKE) clean_build package

clean: clean_build
	$(Q)rm -rf build dist osm_nbi.egg-info deb deb_dist *.gz $(OUT_DIR) $(TREES_DIR)

clean_build:
	rm -rf build
	find osm_nbi -name '*.pyc' -delete
	find osm_nbi -name '*.pyo' -delete

package:
	tox -e build

test:
	echo "TODO"

