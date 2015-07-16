#!/bin/bash

dummy_pwd=fairezine
NC='\033[0m'
BLUE='\033[0;34m'
LBLUE='\033[1;34m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
GRAY='\033[1;30m'
RED='\033[0;31m'


wget http://www.rezine.org/files/header-install-propolis.txt -q -O -

echo -e "${LGREEN}
  _____________________________________________________________________________________________${NC}

                  Vous êtes sur le point de configurer une Propolis de Rézine

  * Tous les mots de passe seront : ${RED}\e[4m${dummy_pwd}${NC}\e[24m (à changer après l'execution de ce script)

  * Ce script a besoin d'être executé en temps que root ${RED}\e[4mSUR${NC}\e[24m la brique à partir d'une image 
    labriqueinternet_04-06-2015_jessie.img installée sur la carte SD
     
  * Si vous rencontrez des problèmes, référez-vous à la documentation originale : 
                        https://yunohost.org/installation_brique_fr${LGREEN}
  _____________________________________________________________________________________________
\n\n${LBLUE}"

read -rsp $'Pressez n\'importe quelle touche pour commencer la configuration...\n' -n1 yolo

# Exit if any of the following command fails
set -e

get_variables() {

    if [ -f rezine.variables ]; then
        source rezine.variables
    else
	echo
	echo -e "${LGREEN}Choisissez un nom pour votre Propolis (nom avec laquelle elle apparaîtra sur le réseau, sans majuscules ni espaces)${NC}"
	read proponame
        echo
        echo -e "${LGREEN}Domaine principal (sera utilisé pour héberger vos emails et autres services)\n${GRAY}i.e.: example.org${NC}"
        read domain
        echo
        echo -e "${LGREEN}Domaine additionnel (par exemple, si vous voulez un domaine différent du précédent pour vos emails)\n${GRAY}i.e.: example2.org (ou laisser vide)${NC}"
        read additional_domain
        echo
        echo -e "${LGREEN}Nom d'utilisateur (utilisé pour se connecter à l'interface et acceder à vos applications. Doit être composé de minuscules et de chiffres seulement)\n${GRAY}i.e.: jonsnow${NC}"
        read username
        echo
        echo -e "${LGREEN}Prénom (obligatoire, utilisé pour l'envoi des mails)\n${GRAY}i.e.: Jon${NC}"
        read firstname
        echo
        echo -e "${LGREEN}Nom (obligatoire, utilisé pour l'envoi des mails)\n${GRAY}i.e. Snow${NC}"
        read lastname
        echo
        echo -e "${LGREEN}Email (doit contenir un des domaines précédemments configurés)\n${GRAY}i.e. jon@example.com${NC}"
        read email
        echo
        echo -e "${LGREEN}Login de votre tunnel chiffré Rézine\n${GRAY}Il est accessible depuis votre espace à cette adresse : https://ambre.rezine.org/vpn_services/ en cliquant sur 'Détails techniques'${NC}"
        read vpn_username
        echo
        echo -e "${LGREEN}Mot de passe de votre tunnel chiffré Rézine\n${GRAY}Il est accessible depuis votre espace à cette adresse : https://ambre.rezine.org/vpn_services/ en cliquant sur 'Détails techniques'\n[ATTENTION !] Bien vérifier de n'avoir aucun espace avant ou après le mot de passe !${NC}"
        read vpn_pwd
        echo
        echo -e "${LGREEN}Nom du SSID de votre hotspot Wifi (le nom du réseau Wifi qui sera actif à la fin de cette configuration)\n${GRAY}i.e.: RezineReseauNeutre${NC}"
        read wifi_ssid
        echo
        echo -e "${LGREEN}Installer DKIM ? (recommandé si vous voulez un serveur email parfait, sinon, pas nécessaire)\n${GRAY}(oui/non)${NC}"
        read install_dkim
        echo
        echo -e "${LGREEN}Installer l'appli TorClient ?\n${GRAY}(oui/non)${NC}"
        read install_tor
	echo
	if [ "$install_tor" = "oui" ]; then
	   echo -e "${LGREEN}Nom du SSID de votre hotspot pour Tor\n${GRAY}i.e.: MonReseauTor${NC}"
           read tor_ssid
           echo
	fi
        echo -e "${LGREEN}Installer l'appli PirateBox ?\n${GRAY}(oui/non)${NC}"
        read install_pirate
        echo
	if [ "$install_pirate" = "oui" ]; then            
           echo -e "${LGREEN}Nom du SSID de votre hotspot pour la PirateBox\n${GRAY}i.e.: ShareBox${NC}"
           read pirate_ssid
           echo
	   echo -e "${LGREEN}Choisir un nom pour la PirateBox\n${GRAY}i.e.: PirateBox${NC}"
	   read pirate_name 
	   echo
	   echo -e "${LGREEN}Choisissez un "faux domaine" pour ${pirate_name}\n${GRAY}i.e.: share.box${NC}"
	   read pirate_dns
	   echo
        fi
        echo -e "\n${LGREEN}L'installation va commencer… merci de bien vérifier une dernière fois les paramètres ci-dessus.${BLUE}"
        read -rsp $'Pressez n\'importe quelle touche pour continuer...\n' -n1 yolo
        echo -e "${NC}\n"

        # Store all the variables into a file
        for var in proponame domain additional_domain username firstname lastname email vpn_username vpn_pwd wifi_ssid install_dkim install_tor tor_ssid install_pirate pirate_ssid pirate_name pirate_dns; do
            declare -p $var | cut -d ' ' -f 3- >> rezine.variables
        done
    fi
}

modify_hostname() {
    echo -e "${LGREEN}"
    echo -e " ============================= "
    echo -e " Modification du nom réseau..."
    echo -e " ============================= ${NC}\n"

    echo "$proponame" > /etc/hostname
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

modify_hosts() {
    # to resolve the domain properly
    echo -e "${LGREEN}"
    echo -e " ========================= "
    echo -e " Modification des hôtes... "
    echo -e " ========================= ${NC}\n"

    grep -q "olinux" /etc/hosts \
      || echo "127.0.0.1 $domain $additional_domain $proponame" >> /etc/hosts
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
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

    yunohost tools postinstall -d $domain -p $dummy_pwd
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

add_additional_domain() {
    # Often we want to add a domain that is not the main domain
    if [ ! -z "$additional_domain" ]; then
        echo -e " =================================================== "
        echo -e " Ajout du domaine additionnel $additional_domain ..."
        echo -e " =================================================== ${NC}\n"

        yunohost domain add $additional_domain
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
}

fix_userdir_creation() {
    echo -e "${LGREEN}"
    echo -e " ====================================================================== "
    echo -e " Ajout d'un script qui crée proprement les répertoire d'utilisateurs..."
    echo -e " ====================================================================== ${NC}\n"

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
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

create_yunohost_user() {
    echo -e "${LGREEN}"
    echo -e " =========================================== "
    echo -e " Création du premier utilisateur YunoHost..."
    echo -e " =========================================== ${NC}\n"

    yunohost user create $username -f $firstname -l $lastname -m $email \
      -q 0 -p $dummy_pwd
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

install_vpnclient() {
    echo -e "${LGREEN}"
    echo -e " ======================================================== "
    echo -e " Installation du client VPN (tunnel chiffré de Rézine)..."
    echo -e " ======================================================== ${NC}\n"

    yunohost app install https://github.com/labriqueinternet/vpnclient_ynh \
      --args "domain=$domain&path=/vpnadmin&server_name=tun.rezine.org"
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}


configure_vpnclient() {
    echo -e "${LGREEN}"
    echo -e " ==================================================== "
    echo -e " Configuration de la connection par tunnel chiffré..."
    echo -e " ==================================================== ${NC}\n"

    # Restrict user access to the app
    yunohost app addaccess vpnclient -u $username
    
    # Rézine related: add some VPN configuration directives
    wget http://www.rezine.org/files/config-VPN-propolis.txt -q -O - > /etc/openvpn/client.conf.tpl

    # Copy certificates and keys
    mkdir -p /etc/openvpn/keys
    wget -O /etc/openvpn/keys/ca-server.crt http://www.rezine.org/files/tunnel.rezine.org.pem

    # And credentials
    echo -e "$vpn_username\n$vpn_pwd" > /etc/openvpn/keys/credentials

    # Set rights
    chown admin:admins -hR /etc/openvpn/keys
    chmod 640 -R /etc/openvpn/keys

    # Configure VPN client
    yunohost app setting vpnclient server_name -v "tun.rezine.org"
    yunohost app setting vpnclient server_port -v "1194"
    yunohost app setting vpnclient server_proto -v "udp"
    yunohost app setting vpnclient service_enabled -v "1"
    
    yunohost app setting vpnclient login_user -v "$vpn_username"
    yunohost app setting vpnclient login_passphrase -v "$vpn_pwd"
    
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


    yunohost app install https://github.com/labriqueinternet/hotspot_ynh \
      --args "domain=${domain}&path=/wifiadmin&wifi_ssid=${wifi_ssid}&wifi_passphrase=${dummy_pwd}&firmware_nonfree=yes"
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}


configure_hostpot() {
    echo -e "${LGREEN}"
    echo -e " ========================================= "
    echo -e " Configuration de l'application Hotspot..."
    echo -e " ========================================= ${NC}\n"

    cmd_conf="yunohost app setting hotspot"

    # Removing the persistent Net rules to keep the Wifi device to wlan0
    rm -f /etc/udev/rules.d/70-persistent-net.rules

    # Restrict user access to the app
    yunohost app addaccess hotspot -u ${username}

    # Ensure that the hotspot is activated and that the IPv6 prefix is set
    ${cmd_conf} service_enabled -v "1"

    # Adding hotspots for TorClient and PirateBox
    if [ "$install_tor" = "oui" ]; then
          if [ "$install_pirate" = "oui" ]; then
             ${cmd_conf} ip4_dns0 -v "193.33.56.30|193.33.56.30"
             ${cmd_conf} ip4_dns1 -v "80.67.169.12|80.67.169.12"
             ${cmd_conf} ip4_nat_prefix -v "10.0.242|10.178.195|10.131.222"
             ${cmd_conf} ip6_addr -v "none|none|none"
             ${cmd_conf} ip6_dns0 -v "2001:913::8|2001:913::8|2001:913::8"
             ${cmd_conf} ip6_dns1 -v "2001:910:800::12|2001:910:800::40|2001:910:800::40"
             ${cmd_conf} ip6_net -v "none|none|none"
             ${cmd_conf} multissid -v 3
             ${cmd_conf} wifi_secure -v "1|1|0"
             ${cmd_conf} wifi_ssid -v "$wifi_ssid|$tor_ssid|$pirate_ssid"
             ${cmd_conf} wifi_passphrase -v "${dummy_pwd}|${dummy_pwd}|none"
          else
             ${cmd_conf} ip4_dns0 -v "193.33.56.30|193.33.56.30"
             ${cmd_conf} ip4_dns1 -v "80.67.169.12|80.67.169.12"
             ${cmd_conf} ip4_nat_prefix -v "10.0.242|10.178.195"
             ${cmd_conf} ip6_addr -v "none|none"
             ${cmd_conf} ip6_dns0 -v "2001:913::8|2001:913::8"
             ${cmd_conf} ip6_dns1 -v "2001:910:800::12|2001:910:800::40"
             ${cmd_conf} ip6_net -v "none|none"
             ${cmd_conf} multissid -v 2
             ${cmd_conf} wifi_secure -v "1|1"
             ${cmd_conf} wifi_ssid -v "$wifi_ssid|$tor_ssid"
             ${cmd_conf} wifi_passphrase -v "${dummy_pwd}|{dummy_pwd}"
          fi
    fi

    # Add the service to YunoHost's monitored services
    yunohost service add ynh-hotspot -l /var/log/syslog

    echo -e "${LGREEN}"
    echo -e " ========================= "
    echo -e " Restarting the hotspot..."
    echo -e " ========================= ${NC}\n"
    systemctl restart ynh-hotspot
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

install_tor() {
if [ "$install_tor" = "oui" ]; then
    echo -e "${LGREEN}"
    echo -e " ============================ "
    echo -e " Installation de TorClient..."
    echo -e " ============================ ${NC}\n"

    yunohost app install https://github.com/labriqueinternet/torclient_ynh \
      --args "domain=$domain&path=/torclientadmin"

    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"

fi
}

configure_tor() {
if [ "$install_tor" = "oui" ]; then
    echo -e "${LGREEN}"
    echo -e " ============================= "
    echo -e " Configuration de TorClient..."
    echo -e " ============================= ${NC}\n"

    # Restrict user access to the app
    yunohost app addaccess torclient -u $username

    yunohost app setting torclient service_enabled -v 1
    yunohost app setting torclient wifi_device_id -v 1

    # Add the service to YunoHost's monitored services
    yunohost service add ynh-torclient -l /var/log/syslog

    echo -e "${LGREEN}"
    echo -e " =========================== "
    echo -e " Restarting the torclient..."
    echo -e " =========================== ${NC}\n"
    systemctl restart ynh-torclient
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
fi
}

install_pirate() {
if [ "$install_pirate" = "oui" ]; then
    echo -e "${LGREEN}"
    echo -e " ============================ "
    echo -e " Installation de PirateBox..."
    echo -e " ============================ ${NC}\n"

    yunohost app install https://github.com/labriqueinternet/piratebox_ynh \
      --args "domain=${domain}&path=/piratebox&opt_chat=yes&opt_deleting=yes&opt_renaming=yes&opt_domain=${pirate_dns}&opt_name=${pirate_name}"

    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
fi
}

configure_pirate() {
if [ "$install_pirate" = "oui" ]; then
    echo -e "${LGREEN}"
    echo -e " ============================= "
    echo -e " Configuration de PirateBox..."
    echo -e " ============================= ${NC}\n"

    # Restrict user access to the app
    yunohost app addaccess piratebox -u $username

    yunohost app setting piratebox service_enabled -v 1
    if [ "$install_tor" = "oui" ]; then
    yunohost app setting piratebox wifi_device_id -v 2
    else
    yunohost app setting piratebox wifi_device_id -v 1
    fi

    # Add the service to YunoHost's monitored services
    yunohost service add ynh-torclient -l /var/log/syslog

    echo -e "${LGREEN}"
    echo -e " =========================== "
    echo -e " Restarting the piratebox..."
    echo -e " =========================== ${NC}\n"
    systemctl restart ynh-piratebox
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
fi
}


# ----------------------------------
# Optional steps
# ----------------------------------

fix_yunohost_services() {
    echo -e "${LGREEN}"
    echo -e " ========================================= "
    echo -e " Ajout/suppression de certains services..."
    echo -e " ========================================= ${NC}\n"

    yunohost service add dnsmasq -l /var/log/syslog \
    || echo "dnsmasq already listed in services"
    yunohost service add nslcd -l /var/log/syslog \
    || echo "nslcd already listed in services"
    yunohost service add spamassassin -l /var/log/mail.log \
    || echo "spamassassin already listed in services"
   
    yunohost service remove bind9 || echo "Bind9 already removed"

    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}


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

add_vpn_restart_cron() {
    echo -e "${LGREEN}"
    echo -e " ========================================================================= "
    echo -e " Ajout d'une tâche cron pour s'assurer que le tunnel chiffré fonctionne..."
    echo -e " ========================================================================= ${NC}\n"

    echo "* * * * * root /sbin/ifconfig tun0 > /dev/null 2>&1 || systemctl restart ynh-vpnclient" > /etc/cron.d/restart-vpn
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
}

configure_DKIM() {
    if [ "$install_dkim" = "oui" ]; then
    echo -e "${LGREEN}"
    echo -e " ======================== "
    echo -e " Configuration de DKIM..."
    echo -e " ======================== ${NC}\n"

    git clone https://github.com/polytan02/yunohost_auto_config_basic
    pushd yunohost_auto_config_basic
    source ./5_opendkim.sh
    popd
    echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
}

display_win_message() {
    ip6=$(ifconfig | grep -C4 tun0 | awk '/inet6 addr/{print $3}' | sed 's/\/64//' || echo 'ERROR')
#    ip4=$(ifconfig | grep -C4 tun0 | awk '/inet addr/{print substr($2,6)}' || echo 'ERROR')
    ip4=$(ifconfig tun0 | grep 'inet adr:' | cut -d: -f2 |  awk '{ print $1}' || echo 'ERROR')

wget http://www.rezine.org/files/footer-install-propolis.txt -q -O -

echo -e "\nVotre Propolis a été correctement configurée."

sleep 2

echo -e "${LGREEN}
--> Veuillez maintenant configurer vos DNS comme ceci :
__________________________________________________________________________${NC}
@ 14400 IN A $ip4
@ 14400 IN AAAA $ip6
_xmpp-client._tcp 14400 IN SRV 0 5 5222 $domain.
_xmpp-server._tcp 14400 IN SRV 0 5 5269 $domain.
@ 14400 IN MX 5 $domain.
@ 14400 IN TXT "v=spf1 a mx ip4:$ip4 -all""
$(cat /etc/opendkim/keys/$domain/mail.txt > /dev/null 2>&1 || echo '')
echo -e "${LGREEN}__________________________________________________________________________${GRAY}
(Pour d'avantage d'information sur la configuration des DNS, visitez 
cette page : ${LBLUE}http://www.rezine.org/documentation/propolis${GRAY})"

    if [ ! -z "$additional_domain" ]; then
        echo -e "[!!] N'oubliez pas égualement de configurer vos enregistrements DNS pour '$additional_domain'"
    fi

echo -e "
\n${LGREEN}--> Et n'oubliez pas de changer :
__________________________________________________________________________${NC}
    
  * Le mot de passe d'administration via l'interface Web de la Propolis :
    ${LBLUE}http://${domain}/yunohost/admin/#/tools/adminpw${NC}

  * Le mot de passe de l'utilisateur via l'interface Web de la Propolis :
    ${LBLUE}http://${domain}/yunohost/admin/#/users/${username}/edit${NC}

  * Le(s) mot(s) de passe Wifi (WPA2) via l'interface Web de la Propolis :
    ${LBLUE}http://${domain}/wifiadmin${NC}
  
  * Et si vous ne l'avez pas fait, le mot de passe root avec la commande :
    ${RED}passwd${LGREEN}
__________________________________________________________________________${NC}"
echo -e "\nEt pour toute question, n'hésitez pas à envoyer un mail à contact@rezine.org\n"
}

# ----------------------------------
# Operation order (you can deactivate some if your script has failed in the middle)
# ----------------------------------

get_variables

modify_hostname
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
install_tor
configure_tor
install_pirate
configure_pirate

remove_dyndns_cron
add_vpn_restart_cron
configure_DKIM

display_win_message

