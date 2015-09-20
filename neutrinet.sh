#!/bin/bash

dummy_pwd=neutrinet

cat <<EOF

You are about to configure an Internet Cube for Neutrinet.
All the passwords will be: '$dummy_pwd' (to change after this script's execution)

/!\\ This script has to be run as root *on* the Cube itself, on a labriqueinternet_04-06-2015_jessie.img SD card
/!\\ If you run into trouble, please refer to the original documentation page: https://yunohost.org/installation_brique_fr

EOF

# Exit if any of the following command fails
set -e

get_variables() {

    if [ -f neutrinet.variables ]; then
        source neutrinet.variables
    else
        echo
        echo "Main domain name (will be used to host your email and services)"
        echo "i.e.: example.com"
        read domain
        echo
        echo "Additional domain name (for example if you want to have a different email domain than the previous one)"
        echo "i.e.: example2.com (or leave blank)"
        read additional_domain
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
        echo "VPN username: "
        read vpn_username
        echo
        echo "VPN password: "
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
        echo "Install DKIM? (recommended if you want a perfect email server, not needed otherwise)"
        echo "(Yes/No)"
        read install_dkim
        echo
        echo
        echo "The installation will proceed, please verify the parameters above one last time."
        read -rsp $'Press any key to continue...\n' -n1 yolo
        echo

        # Store all the variables into a file
        for var in domain additional_domain username firstname lastname email vpn_username vpn_pwd ip6_net wifi_ssid install_dkim; do
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

    grep -q "olinux" /etc/hosts \
      || echo "127.0.0.1 $domain $additional_domain olinux" >> /etc/hosts
}

upgrade_system() {
    echo "Upgrading Debian packages..."

    apt-get update -qq
    apt-get dist-upgrade -y
}

postinstall_yunohost() {
    echo "Launching YunoHost post-installation..."

    yunohost tools postinstall -d $domain -p $dummy_pwd
}

add_additional_domain() {
    # Often we want to add a domain that is not the main domain
    if [ ! -z "$additional_domain" ]; then
        echo "Adding the domain $additional_domain ..."

        yunohost domain add $additional_domain
    fi
}

fix_userdir_creation() {
    echo "Adding a script to properly create user directories..."

    # Temporary FIX to create users directories properly
    mkdir -p /usr/share/yunohost/hooks/post_user_create
    cat > /usr/share/yunohost/hooks/post_user_create/06-create_userdir <<EOF
#!/bin/bash
user=\$1
sudo mkdir -p /var/mail/\$user
sudo chown -hR vmail:mail /var/mail/\$user
/sbin/mkhomedir_helper \$user
EOF

    # Wait 2 seconds in order to let YunoHost give this script a fuck
    sleep 2
}

create_yunohost_user() {
    echo "Creating the first YunoHost user..."

    yunohost user create $username -f "$firstname" -l "$lastname" -m $email \
      -q 0 -p $dummy_pwd
}

install_vpnclient() {
    echo "Installing the VPN client application..."

    yunohost app install https://github.com/labriqueinternet/vpnclient_ynh \
      --args "domain=$domain&path=/vpnadmin&server_name=vpn.neutrinet.be"
}


configure_vpnclient() {
    echo "Configuring the VPN connection..."

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

    yunohost app install https://github.com/labriqueinternet/hotspot_ynh \
      --args "domain=$domain&path=/wifiadmin&wifi_ssid=$wifi_ssid&wifi_passphrase=$dummy_pwd&firmware_nonfree=yes"
}


configure_hostpot() {
    echo "Configuring the hotspot..."

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

fix_yunohost_services() {
    # Add/remove some services to comply to the Cube's services
    yunohost service add dnsmasq -l /var/log/syslog \
      || echo "dnsmasq already listed in services"
    yunohost service add nslcd -l /var/log/syslog \
      || echo "nslcd already listed in services"
    yunohost service add spamassassin -l /var/log/mail.log \
      || echo "spamassassin already listed in services"

    yunohost service remove bind9 || echo "Bind9 already removed"
}

remove_dyndns_cron() {
    yunohost dyndns update > /dev/null 2>&1 \
      && echo "Removing the DynDNS cronjob..." \
      || echo "No DynDNS to remove"

    rm -f /etc/cron.d/yunohost-dyndns
}

add_vpn_restart_cron() {
    echo "Adding a cronjob to ensure the VPN functioning..."

    echo "* * * * * root /sbin/ifconfig tun0 > /dev/null 2>&1 || systemctl restart ynh-vpnclient" > /etc/cron.d/restart-vpn
}

configure_DKIM() {
    if [ "$install_dkim" = "Yes" ]; then
        echo "Configuring the DKIM..."

        git clone https://github.com/polytan02/yunohost_auto_config_basic
        pushd yunohost_auto_config_basic
        source ./5_opendkim.sh
        popd
    fi
}

display_win_message() {
    ip6=$(ifconfig | grep -C4 tun0 | awk '/inet6 addr/{print $3}' | sed 's/\/64//' || echo 'ERROR')
    ip4=$(ifconfig | grep -C4 tun0 | awk '/inet addr/{print substr($2,6)}' || echo 'ERROR')

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

$(cat /etc/opendkim/keys/$domain/mail.txt > /dev/null 2>&1 || echo '')

EOF

    if [ ! -z "$additional_domain" ]; then
        echo "/!\\ Do not forget to configure your DNS records for '$additional_domain' as well"
    fi

    cat <<EOF

/!\\ Do not forget to change:
  * The administration password
  * The user password
  * The root password
  * The Wifi AP password
EOF

}


# ----------------------------------
# Operation order (you can deactivate some if your script has failed in the middle)
# ----------------------------------

get_variables

modify_hosts
upgrade_system

postinstall_yunohost
add_additional_domain
fix_userdir_creation
create_yunohost_user
install_vpnclient
configure_vpnclient
install_hotspot
configure_hostpot

fix_yunohost_services
remove_dyndns_cron
add_vpn_restart_cron
configure_DKIM

display_win_message

