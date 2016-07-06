#! /bin/sh
if [ -s confs/$1.cube ]; then
  echo "confs/$1.cube existe déjà. Le script ne fait rien."
else
cat >confs/$1.cube << EOF
{
 "server_name": "vpn.iloth.net",
 "server_port": "1194",
 "server_proto": "udp",
 "crt_server_ca": "`cat keys/ca.crt | tr '\n' '|'`",
 "crt_client_key": "`cat keys/$1.key |tr '\n' '|'`",
 "crt_client": "`sed -n '/-----BEGIN CERTIFICATE-----/,$p' keys/$1.crt |tr '\n' '|'`",
 "dns0": "89.234.141.66",
 "dns1": "2001:913::8",
 "openvpn_add": ["client","dev tun","comp-lzo no"],
 "openvpn_rm": ["tun-ipv6","pull","nobind","comp-lzo adaptive", "remote-cert-tls server", "ns-cert-type server", "route-ipv6 2000::/3","redirect-gateway def1 bypass-dhcp","tls-client"]
}
EOF
### PAS DE DH pour le moment !!!
echo "confs/$1.cube créé et prêt à être envoyé au client."
echo "Pensez à créer le fichier ccd/$1 avec l'ip associé au vpn"
fi
