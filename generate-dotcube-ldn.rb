#!/usr/bin/env ruby
#
# Copyright (C) 2015 Sebastien Badia <seb@sebian.fr>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2 of
# the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# http://internetcu.be/dotcubefiles.html
# https://wiki.ldn-fai.net/wiki/Ajouter_un_compte_VPN

require 'json'
require 'yaml'

if ARGV.length != 1
  puts "generate-dotcube.rb LOGIN"
  exit 1
end

user = ARGV[0]
vpn = {}
common = JSON.load(File.read('/srv/dotcube/dotcube-common.json'))
yaml = YAML.load_file('/srv/puppet/production/puppet/hiera/ldn.yaml')

if ! File.exist?("/srv/ca-openvpn-clients/keys/#{user}.crt")
  puts "user #{user} seems not present..."
  exit 1
end

vpn['ip6_net'] = yaml['openvpn::users'][user]['prefix']
vpn['ip4_addr'] = yaml['openvpn::users'][user]['ipv4']
vpn['crt_server_ca'] = File.read('/root/ca_server.crt').strip.tr("\n", '|')
vpn['crt_client'] = File.read("/srv/ca-openvpn-clients/keys/#{user}.crt").strip.tr("\n", '|')[/-----.*-----/]
vpn['crt_client_key'] = File.read("/srv/ca-openvpn-clients/keys/#{user}.key").strip.tr("\n", '|')

File.open("/srv/dotcube/#{user}.cube","w") do |f|
  f.write(JSON.pretty_generate(common.merge(vpn)))
end
puts "dotcube file generated /srv/dotcube/#{user}.cube"
