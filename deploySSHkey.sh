#!/bin/bash
################################################################################################
# About: Script used to deploy SSH keys to multiple servers.
# Usage: Execute deploySSHkey.sh
# Requires: SSH Public Key file to be created.  AD account on server.
# Target: Remote Hosts
# Options: None
# Author: Brian McAlister (BAH)
# Last Update: 27 JUL 2024
################################################################################################

### VARIABLES ###
DOMAIN="EXAMPLE"
SSH_USER="${USERNAME}"
SSH_KEY="/c/Users/${SSH_USER}/.ssh/${SSH_USER}.${DOMAIN,,}.pub"
SCRIPT_PATH="$(dirname "${BASH_SOURCE}")"
REMOTE_SERVERS=$1
REMOTE_SERVERS_LIST="deploySSHkey_server_list.txt"
REMOTE_SERVERS_LIST_LOC="${SCRIPT_PATH}/${REMOTE_SERVERS_LIST}"

#### Text Color Formats ####
Red=$(tput setaf 1)     #${Red}
Green=$(tput setaf 2)   #${Green}
Blue=$(tput setaf 4)    #${Blue}
Bold=$(tput bold)       #${Bold}
Reset=$(tput sgr0)      #${Reset}

### FUNCTIONS ###
check_remote_servers() {
if [ -z "${REMOTE_SERVERS}" ]; then
	REMOTE_SERVERS=$(cat ${REMOTE_SERVERS_LIST_LOC} 2>/dev/null)
	if [ -z "${REMOTE_SERVERS}" ]; then
		echo "${Reset}${Bold}${Red}WARNING! Remote server list input file not found!${Reset}"
		echo "${Reset}${Bold}${Green}Expected location and name: ${REMOTE_SERVERS_LIST_LOC}${Reset}"
		echo "${Reset}${Bold}${Blue}Querying AWS for RHEL instances!${Reset}"
		REMOTE_SERVERS=$(aws ec2 describe-instances --output table --query 'Reservations[].Instances[].[InstanceId, State.Name, PrivateIpAddress, Tags[?Key==`Environment`].Value|[0], Tags[?Key==`OSName`].Value|[0]]' --filters "Name=tag:OSName,Values=Red Hat Enterprise Linux *" | grep 'Red Hat' | tr -d '|' | sed 's/Red Hat Enterprise Linux /RHEL/g' | grep 'i-' | grep 'running' | awk '{print $3}')
		if [ -z "${REMOTE_SERVERS}" ]; then
			echo "${Reset}${Bold}${Red}ERROR! AWS query returned 0 instances!${Reset}"
			echo "${Reset}${Bold}${Blue}Exiting!${Reset}"
			exit 1
		fi
	fi
fi
echo "${Reset}${Bold}${Green}This script will attempt to deploy public SSH key(s) to the following servers:${Reset}"
echo "${REMOTE_SERVERS}"
read -p "Do you want to proceeed? [y/n] " ANSWER
if ! [[ "$ANSWER" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
	echo "${Reset}${Bold}${Blue}Exiting!${Reset}"
	exit 1
fi
}

check_ssh_key_file() {
if ! [ -s "${SSH_KEY}" ]; then
    echo "${Reset}${Bold}${Red}ERROR! SSH public key file not found!${Reset}"
    echo "${Reset}${Bold}${Green}Expected location and name: ${SSH_KEY}${Reset}"
    echo "${Reset}${Bold}${Blue}Exiting!${Reset}"
    exit 1
else
	echo "${Reset}${Green}Using \"${SSH_KEY}\" key.${Reset}"
fi
}

check_AD_creds() {
result=$(powershell.exe -Command "& { 
	param(\$Username, \$Password, \$Domain)
	\$securePassword = ConvertTo-SecureString -String \"\$Password\" -AsPlainText -Force
    \$creds = New-Object System.Management.Automation.PSCredential(\"\$Domain\\\$Username\", \$securePassword)
	\$process = Start-Process 'C:\windows\system32\notepad.exe' -Credential \$creds -PassThru
	if(\$process.Id) {
		Write-Output 'true'
		Stop-Process -Id \$process.Id
	} else {
		Write-Output 'false'
	}
}" -Username "${SSH_USER}" -Password "${ADPASS}" -Domain "${DOMAIN}" 2>/dev/null)

#DEBUG
#Write-Output \"PASSWORD: \$credential.Password, USERNAME: \$credential.UserName, INPUT: \$Username, INPUT: \$Password, SECURE: \$securePassword\"
#Write-Output \"PASSWORD: \$(\$credential.GetNetworkCredential().Password), USERNAME: \$(\$credential.GetNetworkCredential().UserName)\";
#echo ${result}

if [ "$result" == "true" ]; then
	echo "${Reset}${Green}Your password matches what is in Active Directory...proceeding!${Reset}"
else
	echo "${Reset}${Bold}${Red}ERROR! Your password does NOT match what is in Active Directory.${Reset}"
	echo "${Reset}${Bold}${Blue}Exiting!${Reset}"
	exit 1
fi
}

get_AD_creds() {
read -sp "${Reset}${Green}Enter AD password: ${Reset}" ADPASS
echo ""
check_AD_creds;
echo "${Reset}${Bold}${Blue}Installing Public SSH key for user ${SSH_USER} on the following servers:${Reset}"
}


deploy_key() {
for IP in ${REMOTE_SERVERS}; do
	echo -n "${Reset}${Green}Deploying to server ${IP}....${Reset}"
	if ! echo y | plink -ssh "${SSH_USER}"@"${IP}" -pw "${ADPASS}" "grep -q \"$(cat ${SSH_KEY})\" ~/.ssh/authorized_keys"; then
		echo y | plink -ssh "${SSH_USER}"@"${IP}" -pw "${ADPASS}" "mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys" < "${SSH_KEY}"
		echo "${Reset}${Bold}${Green}Done!${Reset}"
	else
		echo "${Reset}${Bold}${Red}Already present!${Reset}"
	fi
done
}

### ORCHESTRATION ###
check_remote_servers;
check_ssh_key_file;
get_AD_creds;
deploy_key;
unset ADPASS

exit 0
