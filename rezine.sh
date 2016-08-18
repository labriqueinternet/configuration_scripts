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

(Propolis : matériau recueilli par les abeilles à partir de certains végétaux. Cette résine végétale est
utilisée par les abeilles comme mortier et anti-infectieux pour assainir la ruche.


  * Tous les mots de passe seront : ${RED}\e[4m${dummy_pwd}${NC}\e[24m (à changer après l'execution de ce script)

  * Ce script a besoin d'être executé en temps que root ${RED}\e[4mSUR${NC}\e[24m la brique à partir d'une image
    labriqueinternet_04-06-2015_jessie.img installée sur la carte SD

  * Si vous rencontrez des problèmes, référez-vous à la documentation originale :
                        https://yunohost.org/installation_brique_fr${LGREEN}
  _____________________________________________________________________________________________
\n\n${LBLUE}"

read -rsp $'La configuration va commencer. À tout moment, si vous avez fait une erreur dans les questions, vous pouvez arreter avec Ctrl+C pour arrêter le script puis recommencer la procédure. Pressez n\'importe quelle touche pour commencer la configuration...\n' -n1 yolo

# Exit if any of the following command fails
set -e

get_variables() {

    if [ -f rezine.variables ]; then
        source rezine.variables
    else
	echo -e "${NC}Veuillez rentrer les valeurs qui vous sont demandées. Pour les valeurs optionnelles, vous pouvez taper sur entrée pour passer à la configuration suivante"
	echo
	echo -e "${RED}[Optionnel] ${LGREEN}Choisissez un nom pour votre Propolis (nom avec laquelle elle apparaîtra sur le réseau, sans majuscules ni espaces)${NC}"
	read proponame
	   if [ -z "${proponame}" ]; then
	       proponame="propolis"
	   fi
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Domaine principal (sera utilisé pour héberger vos emails et autres services)\n${GRAY}ex: example.org${NC}"
        read domain
        echo
        echo -e "${RED}[Optionnel] ${LGREEN}Domaine additionnel (par exemple, si vous voulez un domaine différent du précédent pour vos emails)\n${GRAY}ex: example2.org${NC}"
        read additional_domain
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
        echo -e "${RED}[Obligatoire] ${LGREEN}Login de votre tunnel chiffré Rézine\n${GRAY}Il est accessible depuis votre espace à cette adresse : https://ambre.rezine.org/vpn_services/ en cliquant sur 'Détails techniques'${NC}"
        read vpn_username
        echo
        echo -e "${RED}[Obligatoire] ${LGREEN}Mot de passe de votre tunnel chiffré Rézine\n${GRAY}Il est accessible depuis votre espace à cette adresse : https://ambre.rezine.org/vpn_services/ en cliquant sur 'Détails techniques'\n[ATTENTION !] Bien vérifier de n'avoir aucun espace avant ou après le mot de passe !${NC}"
        read vpn_pwd
        echo
        echo -e "${RED}[Optionnel] ${LGREEN}Nom du SSID de votre hotspot Wifi (le nom du réseau Wifi qui sera actif à la fin de cette configuration)\n${GRAY}Defaut: RezineReseauNeutre${NC}"
        read wifi_ssid
           if [ -z "${wifi_ssid}" ]; then
               wifi_ssid="RezineReseauNeutre"
           fi
        echo
        echo -e "${RED}[Optionnel] ${LGREEN}Installer DKIM ? (recommandé si vous voulez un serveur email parfait)\n${GRAY}(oui/non)${NC}"
        read install_dkim
        echo
	echo -e "${LGREEN}Voulez-vous installer la ou les applications supplémentaires : TorClient / PirateBox ?\n${GRAY}(oui/non)${NC}"
	read install_apps
	echo
	if [ "$install_apps" = "oui" ]; then
	   if dmesg | grep "idVendor=13d3" | grep "idProduct=3327" >/dev/null; then
              wifi_atheros="yes"
	   fi
	   if dmesg | grep "idVendor=148f" | grep "idProduct=5370" >/dev/null; then
	      wifi_realtek="yes"
	   fi
	   if [ -n "${wifi_atheros}" ]; then
	      echo -e "${RED}[ATTENTION !] Votre antenne Wifi ne vous permettra pas de créer plus que 2 hotspots. De ce fait, vous ne pourrez installer qu'une seule des deux applications supplémentaires. Ce sera donc entrée OU dessert !\n${LGREEN}Veuillez choisir l'application à installer en tapant «pirate» ou «tor»${NC}"
	      read app_atheros
	      if [ "${app_atheros}" = "tor" ]; then
	         install_tor="oui" install_pirate="non" pirate_ssid="" pirate_name="" pirate_dns=""
	      fi
	      if [ "${app_atheros}" = "pirate" ]; then
	         install_pirate="oui" install_tor="non" tor_ssid=""
	      fi
	      echo
	   fi
	   if [ -z "${wifi_realtek}" -a -z "${wifi_atheros}" ]; then
	      echo -e "${RED}[ATTENTION !] Votre antenne Wifi ne fait pas partie des antennes préconisées pour la Brique Internet. Pour éviter tout problème lié au nombre de points d'accès réalisables par votre antenne, il est préférable que vous installiez vous-même ces deux applications dans l'interface d'administration après cette phase de configuration."
	      wifi_unknown="yes"
	      install_tor="non" install_pirate="non"
	   fi
           if [ -n "${wifi_realtek}" ]; then
	      echo -e "${RED}[Optionnel] ${LGREEN}Installer l'appli TorClient ?\n${GRAY}(oui/non)${NC}"
              read install_tor
	      echo
	   fi
	   if [ "${install_tor}" = "oui" ]; then
	      echo -e "${RED}[Optionnel] ${LGREEN}Nom du SSID de votre hotspot pour Tor\n${GRAY}Defaut: MonReseauTor${NC}"
              read tor_ssid
                 if [ -z "${tor_ssid}" ]; then
                     tor_ssid="MonReseauTor"
                 fi
              echo
	   else
	      tor_ssid=""
	   fi
	   if [ -n "${wifi_realtek}" ]; then
              echo -e "${RED}[Optionnel] ${LGREEN}Installer l'appli PirateBox ?\n${GRAY}(oui/non)${NC}"
              read install_pirate
	      echo
	   fi
	   if [ "${install_pirate}" = "oui" ]; then
              echo -e "${RED}[Optionnel] ${LGREEN}Nom du SSID de votre hotspot pour la PirateBox\n${GRAY}Defaut: ShareBox${NC}"
              read pirate_ssid
                 if [ -z "${pirate_ssid}" ]; then
                     pirate_ssid="ShareBox"
                 fi
              echo
	      echo -e "${RED}[Optionnel] ${LGREEN}Choisir un nom pour la PirateBox\n${GRAY}Defaut: PirateBox${NC}"
	      read pirate_name
                 if [ -z "${pirate_name}" ]; then
                     pirate_name="PirateBox"
                 fi
	      echo
	      echo -e "${RED}[Optionnel] ${LGREEN}Choisissez un "faux domaine" pour ${pirate_name}\n${GRAY}Defaut: share.box${NC}"
	      read pirate_dns
                 if [ -z "${pirate_dns}" ]; then
                     pirate_dns="share.box"
                 fi
	      echo
	   else
	      pirate_ssid="" pirate_name="" pirate_dns=""
           fi
	else
	   install_tor="non" tor_ssid="" install_pirate="non" pirate_ssid="" pirate_name="" pirate_dns=""
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
    if [ -f /etc/yunohost/installed ]; then
        echo -e "${LGREEN}"
        echo -e " ## La post-installation a déjà eu lieu, passage à la suite... ##\n"
    else
        yunohost tools postinstall -d $domain -p $dummy_pwd
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
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
    echo -e " Installation du client VPN (tunnel chiffré de Rézine)..."
    echo -e " ======================================================== ${NC}\n"

    if [ -n "$(yunohost app info vpnclient)" ]; then
        echo -e "${LGREEN}"
        echo -e " ## L'application vpnclient est déjà installée, passage à la suite... ##\n"
    else
        yunohost app install https://github.com/labriqueinternet/vpnclient_ynh \
          --args "domain=$domain&path=/vpnadmin&server_name=tun.rezine.org"
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

    # Rézine related: add some VPN configuration directives
    wget http://www.rezine.org/files/config-VPN-propolis.txt -q -O - > /etc/openvpn/client.conf.tpl

    # Copy certificates and keys
    mkdir -p /etc/openvpn/keys
    wget -O /etc/openvpn/keys/ca-server.crt http://www.rezine.org/files/tunnel.rezine.org.pem
    chown admin:admins /etc/openvpn/keys/ca-server.crt && chmod 644 /etc/openvpn/keys/ca-server.crt

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

   if [ -n "$(yunohost app info hotspot)" ]; then
        echo -e "${LGREEN}"
        echo -e " ## L'application hotspot est déjà installée, passage à la suite... ##\n"
    else
        yunohost app install https://github.com/labriqueinternet/hotspot_ynh \
          --args "domain=${domain}&path=/wifiadmin&wifi_ssid=${wifi_ssid}&wifi_passphrase=${dummy_pwd}&firmware_nonfree=yes"
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
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

    if [ -n "$(yunohost app info torclient)" ]; then
        echo -e "${LGREEN}"
        echo -e " ## L'application torclient est déjà installée, passage à la suite... ##\n"
    else
        yunohost app install https://github.com/labriqueinternet/torclient_ynh \
          --args "domain=$domain&path=/torclientadmin"
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
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

    if [ -n "$(yunohost app info piratebox)" ]; then
        echo -e "${LGREEN}"
        echo -e " ## L'application piratebox est déjà installée, passage à la suite... ##\n"
    else
        yunohost app install https://github.com/labriqueinternet/piratebox_ynh \
          --args "domain=${domain}&path=/piratebox&opt_chat=yes&opt_deleting=yes&opt_renaming=yes&opt_domain=${pirate_dns}&opt_name=${pirate_name}"
        echo -e "${LBLUE}\e[1m   ----> Fait ! \e[21m${NC}"
    fi
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

    echo "* * * * * root /bin/ip a s tun0 > /dev/null 2>&1 || systemctl restart ynh-vpnclient" > /etc/cron.d/restart-vpn
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
    ip6=$(ip -6 addr show tun0 | awk -F'[/ ]' '/inet/{print $6}' || echo 'ERROR')
    ip4=$(ip -4 addr show tun0 | awk -F'[/ ]' '/inet/{print $6}' || echo 'ERROR')

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

