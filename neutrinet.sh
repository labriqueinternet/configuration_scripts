#!/bin/bash

dummy_pwd=neutrinet

clear
cat <<EOF

********************************************************************************
You are about to configure an Internet Cube for Neutrinet.
All the passwords; yunohost admin account, openvpn password and the password 
for the AP, will be: '$dummy_pwd'. Consider changing them after installation.

/!\\ This script has to be run as root *on* the Cube itself, on a 
	labriqueinternet_A20LIME_2015-11-09.img SD card (or newer)
/!\\ If you run into trouble, please refer to the original 
	documentation page: https://yunohost.org/installation_brique_fr
/!\\ Be aware that as soon as the vpn goes live the root user can log in over
	the vpn with the chosen password! You might consider revising the root 
	password before continuing. Choosing a dictionary word or 12345678 is 
	not the best thing to do here, instead have a look at 
	https://ssd.eff.org/en/module/creating-strong-passwords for advice on 
	creating a strong password.

Press any key to continue or CTRL-C to abort
EOF
read

# Exit if any of the following command fails
set -e

get_variables() {

    if [ -f neutrinet.variables ]; then
        source neutrinet.variables
	echo "********************************************************************************"
	echo The following settings will apply
	echo ""
	echo domain = $domain
	echo username = $username
	echo firstname = $firstname
	echo lastgname = $lastname
	echo email = $email
	echo vpn_username = $vpn_username
	echo "vpn_pwd = **********"
	echo ip6_net = $ip6_net
	echo wifi_ssid = $wifi_ssid
	echo vpn_ca_crt = ${vpn_ca_crt:0:46}...
	echo vpn_client_key = ${vpn_client_key:0:46}...
	echo vpn_client_crt = ${vpn_client_crt:0:46}...
	echo ""
	echo "********************************************************************************"
	echo Press any key to continue or CTRL-C to abort
	read
    else
        echo
        echo "Main domain name (will be used to host your email and services)"
        echo "i.e.: example.com"
        read domain
        echo
        echo "Username (used to connect to the user interface and access your apps, must be composed of lowercase letters and numbers only)"
        echo "i.e.: jonsnow"
        read username
        echo
        echo "Firstname (mandatory, used as your firstname when you send emails)"
        echo "i.e.: Jon"
        read firstname
        echo
        echo "Lastname (mandatory, used as your lastname when you send emails)"
        echo "i.e. Snow"
        read lastname
        echo
        echo "Email (must contain one of the domain previously entered as second part)"
        echo "i.e. jon@example.com"
        read email
        echo
        echo "VPN client certificate (paste all the content of client.crt below and end with a blank line): "
        vpn_client_crt=$(sed '/^$/q' | sed 's/-----BEGIN CERTIFICATE-----//' | sed 's/-----END CERTIFICATE-----//' | sed '/^$/d')
        echo
        echo "VPN client key (paste all the content of client.key below and end with a blank line): "
        vpn_client_key=$(sed '/^$/q' | sed 's/-----BEGIN PRIVATE KEY-----//' | sed 's/-----END PRIVATE KEY-----//' | sed '/^$/d')
        echo
        echo "CA server certificate (paste all the content of ca.crt below and end with a blank line): "
        vpn_ca_crt=$(sed '/^$/q' | sed 's/-----BEGIN CERTIFICATE-----//' | sed 's/-----END CERTIFICATE-----//' | sed '/^$/d')
        echo
        echo "VPN username (first line of the 'auth' file): "
        read vpn_username
        echo
        echo "VPN password (second line of the 'auth' file): "
        read vpn_pwd
        echo
        echo "IPv6 delegated prefix (without trailing /56, to be found in the neutrinet MGMT interface)"
        echo "i.e.: 2001:913:1000:300::"
        read ip6_net
        echo
        echo "WiFi AP SSID (that will appear right after this configuration script ending)"
        echo "i.e.: MyWunderbarNeutralNetwork"
        read wifi_ssid
        echo
        echo
        echo "The installation will proceed, please verify the parameters above one last time."
        read -rsp $'Press any key to continue...\n' -n1 yolo
        echo

        # Store all the variables into a file
        for var in domain username firstname lastname email vpn_username vpn_pwd ip6_net wifi_ssid; do
            declare -p $var | cut -d ' ' -f 3- >> neutrinet.variables
        done

        echo "vpn_client_crt=\"$vpn_client_crt\"" >> neutrinet.variables
        echo "vpn_client_key=\"$vpn_client_key\"" >> neutrinet.variables
        echo "vpn_ca_crt=\"$vpn_ca_crt\"" >> neutrinet.variables
    fi
}

modify_hosts() {
    # to resolve the domain properly
    echo "Modifying hosts..."

    set -x
    grep -q "olinux" /etc/hosts \
      || echo "127.0.0.1 $domain olinux" >> /etc/hosts
}

upgrade_system() {
    echo "Upgrading Debian packages..."

    set -x
    echo "deb http://repo.yunohost.org/debian jessie stable" > /etc/apt/sources.list.d/yunohost.list

    apt-get update -qq
    
    # untile this 4.5 kernel thing is fixed
    # apt-get dist-upgrade -y
    apt-get install yunohost yunohost-admin moulinette nslcd -y
}

postinstall_yunohost() {
    echo "Launching YunoHost post-installation..."

    set -x
    yunohost tools postinstall -d $domain -p $dummy_pwd
}

create_yunohost_user() {
    echo "Creating the first YunoHost user..."

    set -x
    yunohost user create $username -f "$firstname" -l "$lastname" -m $email \
      -q 0 -p $dummy_pwd
}

install_vpnclient() {
    echo "Installing the VPN client application..."

    set -x
    yunohost app install https://github.com/labriqueinternet/vpnclient_ynh \
      --args "domain=$domain&path=/vpnadmin&server_name=vpn.neutrinet.be"
}


configure_vpnclient() {
    echo "Configuring the VPN connection..."

    set -x
    # Restrict user access to the app
    yunohost app addaccess vpnclient -u $username
    
    # Neutrinet related: add some VPN configuration directives
    cat >> /etc/openvpn/client.conf.tpl <<EOF

resolv-retry infinite
ns-cert-type server
topology subnet
EOF

    # Copy certificates and keys
    mkdir -p /etc/openvpn/keys
    echo '-----BEGIN CERTIFICATE-----'             > /etc/openvpn/keys/user.crt
    grep -Eo '"[^"]*"|[^" ]*' <<< $vpn_client_crt >> /etc/openvpn/keys/user.crt
    echo '-----END CERTIFICATE-----'              >> /etc/openvpn/keys/user.crt

    echo '-----BEGIN PRIVATE KEY-----'             > /etc/openvpn/keys/user.key
    grep -Eo '"[^"]*"|[^" ]*' <<< $vpn_client_key >> /etc/openvpn/keys/user.key
    echo '-----END PRIVATE KEY-----'              >> /etc/openvpn/keys/user.key

    echo '-----BEGIN CERTIFICATE-----'             > /etc/openvpn/keys/ca-server.crt
    grep -Eo '"[^"]*"|[^" ]*' <<< $vpn_ca_crt     >> /etc/openvpn/keys/ca-server.crt
    echo '-----END CERTIFICATE-----'              >> /etc/openvpn/keys/ca-server.crt

    # And credentials
    echo -e "$vpn_username\n$vpn_pwd" > /etc/openvpn/keys/credentials

    # Set rights
    chown admin:admins -hR /etc/openvpn/keys
    chmod 640 -R /etc/openvpn/keys

    # Configure VPN client
    yunohost app setting vpnclient server_name -v "vpn.neutrinet.be"
    yunohost app setting vpnclient server_port -v "1194"
    yunohost app setting vpnclient server_proto -v "udp"
    yunohost app setting vpnclient service_enabled -v "1"
    
    yunohost app setting vpnclient login_user -v "$vpn_username"
    yunohost app setting vpnclient login_passphrase -v "$vpn_pwd"
    
    yunohost app setting vpnclient ip6_net -v "$ip6_net"

    # Add the service to YunoHost's monitored services
    yunohost service add ynh-vpnclient -l /var/log/openvpn-client.log
    
    echo "Restarting OpenVPN..."
    systemctl restart ynh-vpnclient \
      || (echo "Logs:" && cat /var/log/openvpn-client.log && exit 1)
    sleep 5
}


install_hotspot() {
    echo "Installing the Hotspot application..."

    set -x
    yunohost app install https://github.com/labriqueinternet/hotspot_ynh \
      --args "domain=$domain&path=/wifiadmin&wifi_ssid=$wifi_ssid&wifi_passphrase=$dummy_pwd&firmware_nonfree=yes"
}


configure_hostpot() {
    echo "Configuring the hotspot..."

    set -x
    # Removing the persistent Net rules to keep the Wifi device to wlan0
    rm -f /etc/udev/rules.d/70-persistent-net.rules

    # Restrict user access to the app
    yunohost app addaccess hotspot -u $username

    # Ensure that the hotspot is activated and that the IPv6 prefix is set
    yunohost app setting hotspot service_enabled -v "1"
    yunohost app setting hotspot ip6_net -v "$ip6_net"
    yunohost app setting hotspot ip6_addr -v "${ip6_net}42"

    # Add the service to YunoHost's monitored services
    yunohost service add ynh-hotspot -l /var/log/syslog

    echo "Restarting the hotspot..."
    systemctl restart ynh-hotspot
}


# ----------------------------------
# Optional steps
# ----------------------------------

remove_dyndns_cron() {
    set -x
    yunohost dyndns update > /dev/null 2>&1 \
      && echo "Removing the DynDNS cronjob..." \
      || echo "No DynDNS to remove"

    rm -f /etc/cron.d/yunohost-dyndns
}

restart_api() {
    set -x
    systemctl restart yunohost-api
}

display_win_message() {
    ip6=$(ip -6 addr show tun0 | awk -F'[/ ]' '/inet/{print $6}' || echo 'ERROR')
    ip4=$(ip -4 addr show tun0 | awk -F'[/ ]' '/inet/{print $6}' || echo 'ERROR')

    cat <<EOF

VICTOIRE !

Your Cube has been configured properly. Please set your DNS records as below:

@ 14400 IN A $ip4
* 14400 IN A $ip4
@ 14400 IN AAAA $ip6
* 14400 IN AAAA $ip6
_xmpp-client._tcp 14400 IN SRV 0 5 5222 $domain.
_xmpp-server._tcp 14400 IN SRV 0 5 5269 $domain.

@ 14400 IN MX 5 $domain.
@ 14400 IN TXT "v=spf1 a mx ip4:$ip4 ip6:$ip6 -all"

$(cat /etc/dkim/$domain.mail.txt > /dev/null 2>&1 || echo '')

EOF

    cat <<EOF

/!\\ Do not forget to change:
  * The root password on the OS-level: # passwd
  * The administration password in yunohost
  * The regular user password in yunohost
  * The VPN client password administered in yunohost
  * The Wifi AP password administered in yunohost
EOF

}


# ----------------------------------
# Operation order (you can deactivate some if your script has failed in the middle)
# ----------------------------------

get_variables

modify_hosts
upgrade_system

postinstall_yunohost
create_yunohost_user
install_vpnclient
configure_vpnclient
install_hotspot
configure_hostpot

remove_dyndns_cron
restart_api

display_win_message

