#!/bin/bash
#
# Copyright 2021, luftegrof at duck dot com
#
# Licensed under GPL Version 3
# See LICENSE file for info.
#
# Requires: 
# websocat v1.8.0 | https://github.com/vi/websocat
# vncdotool v0.12.0 | https://github.com/sibson/vncdotool

debug="false"

config_file="./proxmox_typer.conf"
source ${config_file}


echo -n "Proxmox Username: "
read username
if [ -n ${username} ]; then
	echo -n "Proxmox Password: "
	read -s password
	password_enc=$(php -r "echo urlencode(\"${password}\");")
	echo
	if [ -n "${password}" ]; then
		echo -n "Proxmox Realm (pve|pam): "
		read realm
		case "${realm}" in
			pve|pam)
			;;
			*)
				echo -en "Realm must be 'pve' or 'pam'.\n"
				exit 1
			;;
		esac
	else
		echo -en "Password may not be blank.\n"
		exit 1
	fi
else
	echo -en "Username may not be blank.\n"
	exit 1
fi

init=$(curl "https://${proxmox_server}:${proxmox_port}/api2/extjs/access/ticket" \
  --data-raw "username=${username}&password=${password_enc}&realm=${realm}" \
  --compressed \
  --silent \
  --insecure)

if [ "${debug}" == "true" ]; then
	echo ${init}
fi

success=$(echo ${init} | jq -r '.success')

if [ ${success} == 1 ]; then
	proxmox_csrf_token=$(echo ${init} | jq -r '.data.CSRFPreventionToken')
	proxmox_csrf_token_enc=$(php -r "echo urlencode(\"${proxmox_csrf_token}\");")
	proxmox_authn_cookie=$(echo ${init} | jq -r '.data.ticket')
	proxmox_authn_cookie_enc=$(php -r "echo urlencode(\"${proxmox_authn_cookie}\");")
	proxmox_username=$(echo ${init} | jq -r '.data.username')
	if [ "${debug}" == "true" ]; then
		echo -en "proxmox_csrf_token=${proxmox_csrf_token}\n"
		echo -en "proxmox_csrf_token_enc=${proxmox_csrf_token}\n"
		echo -en "proxmox_authn_cookie=${proxmox_authn_cookie}\n"
		echo -en "proxmox_authn_cookie_enc=${proxmox_authn_cookie}\n"
		echo -en "proxmox_username=${proxmox_username}\n"
	fi
else
	echo -en "Proxmox API initialization was not successful.\n"
	exit 1
fi

vncproxy=$(curl https://${proxmox_server}:${proxmox_port}/api2/json/nodes/${proxmox_node}/qemu/${vmid}/vncproxy \
  -H "CSRFPreventionToken: ${proxmox_csrf_token}" \
  -H "Cookie: PVEAuthCookie=${proxmox_authn_cookie_enc}" \
  --data-raw 'websocket=1' \
  --insecure \
  --silent)

vnc_port=$(echo ${vncproxy} | jq -r '.data.port')
vnc_ticket=$(echo ${vncproxy} | jq -r '.data.ticket')
vnc_ticket_enc=$(php -r "echo urlencode(\"$vnc_ticket\");")

if [ "${debug}" == "true" ]; then
	echo ${vnc_ticket}
	echo ${vnc_ticket_enc}
fi

/usr/bin/websocat -k -b \
	-H="Cookie: PVEAuthCookie=${proxmox_authn_cookie_enc}" \
	"tcp-l:${wsproxy_addr}:${wsproxy_port}" \
	"wss://${proxmox_server}:${proxmox_port}/api2/json/nodes/${proxmox_node}/qemu/${vmid}/vncwebsocket?port=${vnc_port}&vncticket=${vnc_ticket_enc}" &

vncdo --force-caps --delay=40 -s ${wsproxy_addr}::${wsproxy_port} -p ${vnc_ticket} typefile mydash.b64

kill `pidof websocat`
