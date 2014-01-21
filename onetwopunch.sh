#!/bin/bash
#
# Original Code for onetwopunch.sh from: Harold Rodriguez
# Original Code found on: http://blog.techorganic.com/
# Modified:  January 21, 2014
# Modified by: MikeDawg
#
# Default usage/error message
echoErrorMsg () {
	echo "Usage $0 network-list(file) [tcp/udp/all]";
}

# No option, show usage message
if [ -z $1 ]; then
	echoErrorMsg
	exit
fi

# No file found, show usage message
if [ ! -f $1 ]; then
	echoErrorMsg
	echo "No file found"
	exit
fi

# Use dateString for backups
dateString=$(date "+%Y%m%d-%H%M%S") 

# 
if [ -z $2 ]; then
	mode="tcp"
elif [ $2 != "udp" ] && [ $2 != "tcp" ] && [ $2 != "all" ] ; then
	echoErrorMsg	
	echo "Protocol type not found"
	exit
else
	mode=$2
fi
 
# backup any old scans before we start a new one
mkdir -p backup
if [ -d ndir ]; then
	mv ndir backup/ndir-$dateString
fi
if [ -d udir ]; then
	mv udir backup/udir-$dateString
fi
 
rm -rf ndir
mkdir -p ndir
rm -rf udir
mkdir -p udir
 
for ip in `cat $1`; do
	echo "[+] scanning ${ip} for $mode ports..."
 
	# unicornscan identifies all open ports
	if [ $mode == "tcp" ]; then
		echo "[+] obtaining all open tcp ports using unicornscan..."
		echo "[+] unicornscan -msf ${ip}:a -l udir/${ip}-tcp.txt"
		unicornscan -msf ${ip}:a -l udir/${ip}-tcp.txt
		ports=$(cat udir/${ip}-tcp.txt | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | tr '\n' ',')
	elif [ $mode == "udp" ]; then
		echo "[+] obtaining all open udp ports using unicornscan..."
		echo "[+] unicornscan -mU ${ip}:a -l udir/${ip}-udp.txt"
		unicornscan -mU ${ip}:a -l udir/${ip}-udp.txt
		ports=$(cat udir/${ip}-udp.txt | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | tr '\n' ',')
	elif [ $mode == "all" ]; then
		echo "[+] obtaining all open ports using unicornscan..."
		echo "[+] unicornscan -mU ${ip}:a -l udir/${ip}-udp.txt"
		unicornscan -mU ${ip}:a -l udir/${ip}-udp.txt
		echo "[+] unicornscan -msf ${ip}:a -l udir/${ip}-tcp.txt"
		unicornscan -msf ${ip}:a -l udir/${ip}-tcp.txt
		ports=$(cat udir/${ip}-*.txt | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | sort -n | uniq | tr '\n' ',')
	fi
 
	# nmap follows up on any open ports unicornscan found
	if [ ! -z $ports ]; then
		echo "[+] ports for nmap to scan: $ports"
		if [ $mode == "tcp" ]; then
			echo "[+] nmap -sV -oX ndir/${ip}-tcp.xml -oG ndir/${ip}-tcp.grep -p ${ports} ${ip}"
			nmap -sV -oX ndir/${ip}-tcp.xml -oG ndir/${ip}-tcp.grep -p ${ports} ${ip}
		elif [ $mode == "udp" ]; then
			echo "[+] nmap -sU -oX ndir/${ip}-udp.xml -oG ndir/${ip}-udp.grep -p ${ports} ${ip}"
			nmap -sU -oX ndir/${ip}-udp.xml -oG ndir/${ip}-udp.grep -p ${ports} ${ip}
		elif [ $mode == "all" ]; then
			echo "[+] nmap -sV -oX ndir/${ip}-tcp.xml -oG ndir/${ip}-tcp.grep -p ${ports} ${ip}"
			nmap -sV -oX ndir/${ip}-tcp.xml -oG ndir/${ip}-tcp.grep -p ${ports} ${ip}
			echo "[+] nmap -sU -oX ndir/${ip}-udp.xml -oG ndir/${ip}-udp.grep -p ${ports} ${ip}"
			nmap -sU -oX ndir/${ip}-udp.xml -oG ndir/${ip}-udp.grep -p ${ports} ${ip}
		fi
	else
		echo "[+] no open ports found"
	fi
	echo ""
done
echo "[+] scans completed"
