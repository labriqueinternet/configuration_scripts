#!/bin/bash

# Run this script on your laptop!
#   % sshfs mirabelle.ldn:/var/www/repo-labriqueinternet /media/pub

local='/media/pub'
date=$1

if [ -z "$date" ]; then
  echo 'please provide an image date!'
  echo '  % publish-image.sh 2016-05-21'
  exit 1
fi

function check_bins() {
  local bins=(btmakemetafile gpg2)

  for i in "${bins[@]}"; do
    if ! which "${i}" &> /dev/null; then
      exit_error "${i} command is required"
    fi
  done
}

check_bins
cd "$local"

for file in labriqueinternet_A20LIME2_encryptedfs_${date}_jessie.img.tar.xz labriqueinternet_A20LIME_encryptedfs_${date}_jessie.img.tar.xz labriqueinternet_A20LIME2_${date}_jessie.img.tar.xz labriqueinternet_A20LIME_${date}_jessie.img.tar.xz
do
  pushd images/
    echo "run on ${file}"
    md5sum "$file" >> MD5SUMS
    btmakemetafile http://ldn-fai.net:6969/announce "$file" --announce_list 'http://ldn-fai.net:6969/announce|udp://tracker.torrent.eu.org:451' --comment 'La Brique Internet : https://labriqueinter.net/' --httpseeds 'http://repo.labriqueinter.net'
    md5sum "${file}.torrent" >> MD5SUMS
    scp "${file}.torrent" ginkgo.ldn:/torrent/btfiles/
    gpg2 -a -b -s --default-key 0xCD8F4D648AC0ECC1 "$file"
  popd
  link=$(echo "$file"|sed 's/'${date}'/latest/g')
  ln -sv "images/${file}" "$link"
done

ssh ginkgo.ldn 'sudo systemctl restart bttrack.service'
