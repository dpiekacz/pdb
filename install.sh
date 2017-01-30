#!/bin/sh
#
apt-get update
apt-get dist-upgrade

apt-get install build-essential autoconf libtool pkg-config python python-dev python3-dev
apt-get install libssl-dev libffi-dev libxslt1-dev libxml2-dev
apt-get install libcurl4-gnutls-dev gnutls-dev
apt-get install letsencrypt
apt-get install redis-server
apt-get install unbound

letsencrypt certonly --standalone -d pdb.gixtools.net

wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
# python3 get-pip.py
rm get-pip.py

pip install --upgrade pip
pip install --upgrade setuptools
pip install pip-review
pip-review -a
pip list --outdated

python -m pip install redis peeringdb flask lxml pygal pygal_maps_world
# python3 -m pip install redis peeringdb flask lxml pygal pygal_maps_world

cp pdb.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable pdb.service
systemctl restart pdb.service
