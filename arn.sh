#!/bin/bash

dummy_pwd=arn-fai.net
NC='\033[0m'
BLUE='\033[0;34m'
LBLUE='\033[1;34m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
GRAY='\033[1;30m'
RED='\033[0;31m'

echo -e "${LGREEN}
  _____________________________________________________________________________________________${NC}

                  Vous êtes sur le point de configurer une Brique d'ARN


  * Tous les mots de passe seront : ${RED}\e[4m${dummy_pwd}${NC}\e[24m (à changer après l'exécution de ce script)

  * Ce script a besoin d'être executé en temps que root ${RED}\e[4mSUR${NC}\e[24m la brique à partir d'une image
    labriqueinternet_A20LIME_2015-11-09.img ou plus récente installée sur la carte SD

  * Si vous rencontrez des problèmes, référez-vous à la documentation originale :
                        https://yunohost.org/installation_brique_fr${LGREEN}
  _____________________________________________________________________________________________
\n\n${LBLUE}"

# Exit if any of the following command fails
set -e

get_variables() {

    if [ -f arn-fai.variables ]; then
        source arn-fai.variables
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
        echo "IPv6 delegated prefix (without trailing /56, to be found in the arn-fai MGMT interface)"
        echo "i.e.: 2001:913:1000:300::"
        read ip6_net
        echo
        echo "WiFi AP SSID (that will appear right after this configuration script ending)"
        echo "i.e.: MyWunderbarNeutralNetwork"
        read wifi_ssid
        echo
        echo "Le dongle wifi est-il propriétaire ?"
        echo "(yes/no)"
        read nonfree_dongle
        echo
        echo
        echo "The installation will proceed, please verify the parameters above one last time."
        read -rsp $'Press any key to continue...\n' -n1 yolo
        echo

        # Store all the variables into a file
        for var in domain username firstname lastname email ip6_net wifi_ssid nonfree_dongle; do
            declare -p $var | cut -d ' ' -f 3- >> arn-fai.variables
        done

        echo "vpn_client_crt=\"$vpn_client_crt\"" >> arn-fai.variables
        echo "vpn_client_key=\"$vpn_client_key\"" >> arn-fai.variables
        echo "vpn_ca_crt=\"$vpn_ca_crt\"" >> arn-fai.variables
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


create_yunohost_user() {
    echo "Creating the first YunoHost user..."

    yunohost user create $username -f "$firstname" -l "$lastname" -m $email \
      -q 0 -p $dummy_pwd
}

install_vpnclient() {
    echo "Installing the VPN client application..."

    yunohost app install https://github.com/labriqueinternet/vpnclient_ynh \
      --args "domain=$domain&path=/vpnadmin&server_name=vpn.arn-fai.net"
}


configure_vpnclient() {
    echo "Configuring the VPN connection..."

    # Restrict user access to the app
    yunohost app addaccess vpnclient -u $username

    # arn-fai related: add some VPN configuration directives
    cat >> /etc/openvpn/client.conf.tpl <<EOF

fragment 1300
mssfix
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

    # Set rights
    chown admin:admins -hR /etc/openvpn/keys
    chmod 640 -R /etc/openvpn/keys

    # Configure VPN client
    yunohost app setting vpnclient server_name -v "vpn.arn-fai.net"
    yunohost app setting vpnclient server_port -v "1194"
    yunohost app setting vpnclient server_proto -v "udp"
    yunohost app setting vpnclient service_enabled -v "1"

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
      --args "domain=$domain&path=/wifiadmin&wifi_ssid=$wifi_ssid&wifi_passphrase=$dummy_pwd&firmware_nonfree=$nonfree_dongle"
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

remove_dyndns_cron() {
    yunohost dyndns update > /dev/null 2>&1 \
      && echo "Removing the DynDNS cronjob..." \
      || echo "No DynDNS to remove"

    rm -f /etc/cron.d/yunohost-dyndns
}


display_win_message() {
    ip6=$(ifconfig tun0 | awk '/adr inet6/{print $3}' | sed 's/\/64//' || echo 'ERROR')
    if [ -z "$ip6" ]; then
        ip6=$(ifconfig tun0 | awk '/inet6 adr/{print $3}' | sed 's/\/64//' || echo 'ERROR')
    fi
    ip4=$(ifconfig tun0 | awk '/inet adr/{print substr($2,5)}' || echo 'ERROR')

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

$(cat /etc/dkim/$domain.mail.txt)

EOF


echo -e "
\n${LGREEN}--> Et n'oubliez pas de changer :
__________________________________________________________________________${NC}

  * Le mot de passe d'administration via l'interface Web de la Brique :
    ${LBLUE}http://${domain}/yunohost/admin/#/tools/adminpw${NC}

  * Le mot de passe de l'utilisateur via l'interface Web de la Brique :
    ${LBLUE}http://${domain}/yunohost/admin/#/users/${username}/edit${NC}

  * Le(s) mot(s) de passe Wifi (WPA2) via l'interface Web de la Brique :
    ${LBLUE}http://${domain}/wifiadmin${NC}

  * Et si vous ne l'avez pas fait, le mot de passe root avec la commande :
    ${RED}passwd${LGREEN}
__________________________________________________________________________${NC}"
echo -e "\nEt pour toute question, n'hésitez pas à envoyer un mail à contact@arn-fai.net\n"

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

display_win_message
