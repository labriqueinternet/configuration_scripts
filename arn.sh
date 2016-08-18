#!/bin/bash

dummy_pwd=arn-fai.net
cubename="Brique"
NC='\033[0m'
BLUE='\033[0;34m'
LBLUE='\033[1;34m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
GRAY='\033[1;30m'
RED='\033[0;31m'

echo -e "${LGREEN}
  _____________________________________________________________________________________________${NC}

                  Vous êtes sur le point de configurer une $cubename d'ARN


  * Tous les mots de passe seront : ${RED}\e[4m${dummy_pwd}${NC}\e[24m (à changer après l'exécution de ce script)

  * Ce script a besoin d'être executé en temps que root ${RED}\e[4mSUR${NC}\e[24m la $cubename à partir d'une image
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
        if [ -z "${hostname}" ]; then
           hostname="brique"
        fi
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Domaine principal (sera utilisé pour héberger vos emails et autres services)\n${GRAY}ex: example.org${NC}"
        read domain
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Nom d'utilisateur (utilisé pour se connecter à l'interface et acceder à vos applications (doit être composé de minuscules et de chiffres seulement)\n${GRAY}ex: jonsnow${NC}"
        read username
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Prénom (utilisé pour l'envoi des mails)\n${GRAY}ex: Jon${NC}"
        read firstname
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Nom (utilisé pour l'envoi des mails)\n${GRAY}ex: Snow${NC}"
        read lastname
        echo
        echo -e "${RED}[Optionnel] ${LGREEN}Email (doit contenir un des domaines précédemments configurés)\n${GRAY}Defaut: ${username}@${domain}${NC}"
        read email
        if [ -z "${email}" ]; then
            email="${username}@${domain}"
        fi
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Certificat VPN client (coller le contenu du fichier XXXXXX.crt et appuyer sur Entrée): "
        vpn_client_crt=$(sed '/^$/q' | sed 's/-----BEGIN CERTIFICATE-----//' | sed 's/-----END CERTIFICATE-----//' | sed '/^$/d')
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Clé privée du VPN (coller le contenu du fichier XXXXXX.key et appuyer sur Entrée): "
        vpn_client_key=$(sed '/^$/q' | sed 's/-----BEGIN PRIVATE KEY-----//' | sed 's/-----END PRIVATE KEY-----//' | sed '/^$/d')
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Certificat CA du serveur (coller le contenu du fichier ca.crt et appuyer sur Entrée): "
        vpn_ca_crt=$(sed '/^$/q' | sed 's/-----BEGIN CERTIFICATE-----//' | sed 's/-----END CERTIFICATE-----//' | sed '/^$/d')
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Préfixe IPv6 délégué (sans /56)\n${GRAY}ex: 2001:913:1000:300::${NC}"
        read ip6_net
        echo
        echo -e "${RED}[Optionnel] ${LGREEN}Nom du SSID de votre hotspot Wifi (le nom du réseau Wifi qui sera actif à la fin de cette configuration)\n${GRAY}Defaut: arn-fai.net${NC}"
        read wifi_ssid
        if [ -z "${wifi_ssid}" ]; then
            wifi_ssid="arn-fai.net"
        fi
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Le dongle wifi est-il propriétaire ?"
        echo "(yes/no)"
        read nonfree_dongle
        echo
        echo
        echo -e "\n${LGREEN}L'installation va commencer… merci de bien vérifier une dernière fois les paramètres ci-dessus.${BLUE}"
        read -rsp $'Pressez n\'importe quelle touche pour continuer...\n' -n1 yolo
        echo -e "${NC}\n"

        # Store all the variables into a file
        for var in domain username firstname lastname email ip6_net wifi_ssid nonfree_dongle; do
            declare -p $var | cut -d ' ' -f 3- >> arn-fai.variables
        done

        echo "vpn_client_crt=\"$vpn_client_crt\"" >> arn-fai.variables
        echo "vpn_client_key=\"$vpn_client_key\"" >> arn-fai.variables
        echo "vpn_ca_crt=\"$vpn_ca_crt\"" >> arn-fai.variables
    fi
}

modify_hostname() {
    echo -e "${LGREEN}"
    echo -e " ============================= "
    echo -e " Modification du nom réseau..."
    echo -e " ============================= ${NC}\n"


    echo "$hostname" > /etc/hostname
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

modify_hosts() {
    # to resolve the domain properly
    echo -e "${LGREEN}"
    echo -e " ========================= "
    echo -e " Modification des hôtes... "
    echo -e " ========================= ${NC}\n"

    grep -q "$hostname" /etc/hosts \
      || echo "127.0.0.1 $domain $hostname" >> /etc/hosts
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

install_free_dongle_drivers() {
    if [ "$nonfree_dongle" = "no" ]; then
        wget -O /lib/firmware/htc_7010.fw "https://github.com/labriqueinternet/hotspot_ynh/raw/master/conf/firmware_htc-7010.fw"
        wget -O /lib/firmware/htc_9271.fw "https://github.com/labriqueinternet/hotspot_ynh/raw/master/conf/firmware_htc-9271.fw"

        echo -e "\n${LGREEN}Les drivers libres du dongle WiFi ont été installés, veuillez débrancher puis rebrancher le dongle WiFi de votre Brique.${BLUE}"
        read -rsp $'Pressez n\'importe quelle touche une fois le dongle rebranché...\n' -n1 yolo
        echo -e "${NC}\n"
    fi
}

upgrade_system() {
    echo -e "${LGREEN}"
    echo -e " ================================= "
    echo -e " Mise à jour des paquets Debian..."
    echo -e " ================================= ${NC}\n"

    apt-get update -qq
    apt-get dist-upgrade -y
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

postinstall_yunohost() {
    echo -e "${LGREEN}"
    echo -e " ================================================ "
    echo -e " Lancement de la post-installation de YunoHost..."
    echo -e " ================================================ ${NC}\n"
    if [ -f /etc/yunohost/installed ]; then
        echo -e "${LGREEN}"
        echo -e " ## La post-installation a déjà eu lieu, passage à la suite... ##\n"
    else
        yunohost tools postinstall -d $domain -p $dummy_pwd
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
}


create_yunohost_user() {
    echo -e "${LGREEN}"
    echo -e " =========================================== "
    echo -e " Création du premier utilisateur YunoHost..."
    echo -e " =========================================== ${NC}\n"

    if [ -n "$(yunohost user list | grep username)" ]; then
        echo -e "${LGREEN}"
        echo -e " ## Il y a déjà un utilisateur principal, passage à la suite... ##\n"
    else
        yunohost user create $username -f $firstname -l $lastname -m $email \
          -q 0 -p $dummy_pwd
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
}

install_vpnclient() {
    echo -e "${LGREEN}"
    echo -e " ======================================================== "
    echo -e " Installation du client VPN (tunnel chiffré d'ARN')..."
    echo -e " ======================================================== ${NC}\n"

    if [ -n "$(yunohost app info vpnclient)" ]; then
        echo -e "${LGREEN}"
        echo -e " ## L'application vpnclient est déjà installée, passage à la suite... ##\n"
    else
        yunohost app install https://github.com/labriqueinternet/vpnclient_ynh \
          --args "domain=$domain&path=/vpnadmin&server_name=vpn.arn-fai.net"
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
}


configure_vpnclient() {
    echo -e "${LGREEN}"
    echo -e " ==================================================== "
    echo -e " Configuration de la connection par tunnel chiffré..."
    echo -e " ==================================================== ${NC}\n"

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

    echo -e "${LGREEN}"
    echo -e " ===================== "
    echo -e " Restarting OpenVPN..."
    echo -e " ===================== ${NC}\n"
    systemctl restart ynh-vpnclient \
      || (echo "Logs:" && cat /var/log/openvpn-client.log && exit 1)
    sleep 5
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}


install_hotspot() {
    echo -e "${LGREEN}"
    echo -e " ======================================== "
    echo -e " Installation de l'application Hotspot..."
    echo -e " ======================================== ${NC}\n"

    if [ -n "$(yunohost app info hotspot)" ]; then
         echo -e "${LGREEN}"
         echo -e " ## L'application hotspot est déjà installée, passage à la suite... ##\n"
    else
        yunohost app install https://github.com/labriqueinternet/hotspot_ynh \
          --args "domain=$domain&path=/wifiadmin&wifi_ssid=$wifi_ssid&wifi_passphrase=$dummy_pwd&firmware_nonfree=$nonfree_dongle"
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
}


configure_hostpot() {
    echo -e "${LGREEN}"
    echo -e " ========================================= "
    echo -e " Configuration de l'application Hotspot..."
    echo -e " ========================================= ${NC}\n"

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

    echo -e "${LGREEN}"
    echo -e " ========================= "
    echo -e " Restarting the hotspot..."
    echo -e " ========================= ${NC}\n"
    systemctl restart ynh-hotspot
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}


# ----------------------------------
# Optional steps
# ----------------------------------

remove_dyndns_cron() {
    yunohost dyndns update > /dev/null 2>&1 \
      && echo -e "${LGREEN}"
         echo -e " ================================== "
         echo -e " Suppression du cron pour DynDNS..."
         echo -e " ================================== ${NC}\n" \
      || echo -e "${LGREEN}"
         echo -e " ========================= "
         echo -e " Pas de Dyndns à supprimer"
         echo -e " ========================= ${NC}\n"

    rm -f /etc/cron.d/yunohost-dyndns
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}


display_win_message() {
    ip6=$(ip -6 addr show tun0 | awk -F'[/ ]' '/inet/{print $6}' || echo 'ERROR')
    ip4=$(ip -4 addr show tun0 | awk -F'[/ ]' '/inet/{print $6}' || echo 'ERROR')

    echo -e "\nVotre $cubename a été correctement configurée."

    sleep 2

    echo -e "${LGREEN}
    --> Veuillez maintenant configurer vos DNS comme ceci :
    __________________________________________________________________________${NC}
    @ 14400 IN A $ip4
    * 14400 IN A $ip4
    @ 14400 IN AAAA $ip6
    * 14400 IN AAAA $ip6
    www 1800 IN CNAME @

    _xmpp-client._tcp 14400 IN SRV 0 5 5222 $domain.
    _xmpp-server._tcp 14400 IN SRV 0 5 5269 $domain.
    muc 1800 IN CNAME @
    pubsub 1800 IN CNAME @
    vjud 1800 IN CNAME @

    @ 14400 IN MX 5 $domain.
    @ 14400 IN TXT \"v=spf1 a mx ip4:$ip4 -all\"
    "

    cat /etc/dkim/$domain.mail.txt || echo ''
    echo -e "${LGREEN}__________________________________________________________________________${GRAY}
    (Pour d'avantage d'information sur la configuration des DNS, visitez
    cette page : ${LBLUE}https://yunohost.org/#/dns_fr${GRAY})"

    echo -e "
    \n${LGREEN}--> Et n'oubliez pas de changer :
    __________________________________________________________________________${NC}

      * Le mot de passe d'administration via l'interface Web de la $cubename :
        ${LBLUE}http://${domain}/yunohost/admin/#/tools/adminpw${NC}

      * Le mot de passe de l'utilisateur via l'interface Web de la $cubename :
        ${LBLUE}http://${domain}/yunohost/admin/#/users/${username}/edit${NC}

      * Le(s) mot(s) de passe Wifi (WPA2) via l'interface Web de la $cubename :
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

modify_hostname
modify_hosts
install_free_dongle_drivers
upgrade_system

postinstall_yunohost
create_yunohost_user
install_vpnclient
configure_vpnclient
install_hotspot
configure_hostpot

remove_dyndns_cron

display_win_message
