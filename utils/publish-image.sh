#!/bin/bash

# LaBriqueInterNet torrent and GPG signatures generator.
# Copyright (C) 2016 Sebastien Badia
# Copyright (C) 2016 LaBriqueInterNet https://labriqueinter.net/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Run this script on your laptop!
# Please read the documentation before :) https://wiki.labriqueinter.net/doku.php/infra:torrent

#   % apt install bittornado
#   % sshfs leela.ldn-fai.net:/var/www/repo.labriqueinter.net /media/pub

opt_debug=false
opt_notracker=false
opt_date=
local_dir='/media/pub'
gpg_key='0xCD8F4D648AC0ECC1'
target_host='bender.ldn-fai.net'

function show_usage() {
  echo -e "\e[1mOPTIONS\e[0m" >&2
  echo -e "  \e[1m-i\e[0m \e[4mdate\e[0m" >&2
  echo -e "     LaBriqueInterNet Image date yyyy-mm-dd format (2016-08-16)" >&2
  echo -e "     \e[2mDefault: No default\e[0m" >&2
  echo -e "  \e[1m-t\e[0m" >&2
  echo -e "     Do not install torrrents (on LDN tracker)" >&2
  echo -e "     \e[2mDefault: Enabled\e[0m" >&2
  echo -e "  \e[1m-d\e[0m" >&2
  echo -e "     Enable debug messages" >&2
  echo -e "  \e[1m-h\e[0m" >&2
  echo -e "     Show this help" >&2
}


function exit_error() {
  local msg=${1}
  local usage=${2}

  if [ ! -z "${msg}" ]; then
    echo -e "\e[31m\e[1m[ERR] $1\e[0m" >&2
  fi

  if [ "${usage}" == usage ]; then
    if [ -z "${msg}" ]; then
      echo -e "\n       \e[7m\e[1m LaBriqueInterNet torrent and GPG signatures generator \e[0m\n"
    else
      echo
    fi

    show_usage
  fi

  exit 1
}

function exit_usage() {
  local msg=${1}

  exit_error "${msg}" usage
}

function exit_normal() {
  exit 0
}

function info() {
  local msg=${1}

  echo -e "\e[32m[INFO] ${msg}\e[0m" >&2
}

function debug() {
  local msg=${1}

  if $opt_debug; then
    echo -e "\e[33m[DEBUG] ${msg}\e[0m" >&2
  fi
}

function check_bins() {
  local bins=(btmakemetafile gpg2 ssh scp md5sum)

  for i in "${bins[@]}"; do
    if ! which "${i}" &> /dev/null; then
      exit_error "${i} command is required"
    fi
  done
}

check_bins

while getopts "i:tdh" opt; do
  case $opt in
    t) opt_notracker=true ;;
    i) opt_date=$OPTARG ;;
    d) opt_debug=true ;;
    h) exit_usage ;;
    \?) exit_usage ;;
  esac
done

if [ -z "$opt_date" ]; then
  exit_error "please provide an image date (format: 2016-05-21)"
fi

cd "$local_dir"

for file in labriqueinternet_A20LIME2_encryptedfs_${opt_date}_jessie.img.tar.xz labriqueinternet_A20LIME_encryptedfs_${opt_date}_jessie.img.tar.xz labriqueinternet_A20LIME2_${opt_date}_jessie.img.tar.xz labriqueinternet_A20LIME_${opt_date}_jessie.img.tar.xz
do
  pushd images/
    echo "run on ${file}"
    md5sum "$file" >> MD5SUMS
    btmakemetafile http://tracker.ldn-fai.net:6969/announce "$file" --announce_list 'http://tracker.ldn-fai.net:6969/announce|udp://tracker.torrent.eu.org:451' --comment 'La Brique Internet : https://labriqueinter.net/' --httpseeds 'http://repo.labriqueinter.net'
    md5sum "${file}.torrent" >> MD5SUMS
    if [ $opt_notracker = false ]; then
      scp "${file}.torrent" "$target_host":/var/lib/bttrack/
      ssh "$target_host" "sudo chown -R bttrack: /var/lib/bttrack"
    fi
    gpg2 -a -b -s --default-key "$gpg_key" "$file"
  popd
  link=$(echo "$file"|sed 's/'${opt_date}'/latest/g')
  ln -svf "images/${file}" "$link"
  ln -svf "images/${file}.asc" "${link}.asc"
  ln -svf "images/${file}.torrent" "${link}.torrent"
done

if [ $opt_notracker = false ]; then
  ssh "$target_host" 'sudo systemctl restart bttrack.service'
fi

echo 'Please update also https://repo.labriqueinter.net/MD5SUMS (if install-sd.sh has changed)'
