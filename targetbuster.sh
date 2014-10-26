#!/bin/bash


##############################################
#
# TargetBuster
# Parse EyeWitness results and run appropriate
# Dirb scan for vulnerable directories.
#
# Updated: 10-24-2014
# 
##############################################

## Setting some variables
apacheWL="/usr/share/dirb/wordlists/vulns/apache.txt"
iisWL="/usr/share/dirb/wordlists/vulns/iis.txt"
tomcatWL="/usr/share/dirb/wordlists/vulns/tomcat.txt"
jbossWL="/usr/share/dirb/wordlists/vulns/jboss.txt"
frontpageWL="/usr/share/dirb/wordlists/vulns/frontpage.txt"
coldfusionWL="/usr/share/dirb/wordlists/vulns/coldfusion.txt"
sharepointWL="/usr/share/dirb/wordlists/vulns/sharepoint.txt"



function main {
	APACHE=$(tac $FILE | awk -F "Server:</b> " 'c&&c--c;/Apache/{c=7}' | grep -iIohE 'https?://[^"]*' | cut -d"<" -f1 | sort -u)
	for line in $APACHE
		do
			echo $line
			output=$(echo ${line}|sed -e 's,http.*://,,g' -e 's/:/-/')
			dirb "$line" "$apacheWL,$WORDLISTS" -r -o ${output}.txt
			unset line
		done

	IIS=$(tac $FILE | awk -F "Server:</b> " 'c&&c--c;/IIS/{c=7}' | grep -iIohE 'https?://[^"]*' | cut -d"<" -f1 | sort -u)
	for line in $IIS
		do
			echo $line
			output=$(echo ${line}|sed -e 's,http.*://,,g' -e 's/:/-/')
			dirb "$line" "$iisWL,$WORDLISTS" -r -o ${output}.txt
			unset line
		done

	TOMCAT=$(tac $FILE | awk -F "Server:</b> " 'c&&c--c;/Tomcat/{c=7}' | grep -iIohE 'https?://[^"]*' | cut -d"<" -f1 | sort -u)
	for line in $TOMCAT
		do
			echo $line
			output=$(echo ${line}|sed -e 's,http.*://,,g' -e 's/:/-/')
			dirb "$line" "$tomcatWL,$WORDLISTS" -r -o ${output}.txt
			unset line
		done

	JBOSS=$(tac $FILE | awk -F "Server:</b> " 'c&&c--c;/JBoss/{c=7}' | grep -iIohE 'https?://[^"]*' | cut -d"<" -f1 | sort -u)
	for line in $JBOSS
		do
			echo $line
			output=$(echo ${line}|sed -e 's,http.*://,,g' -e 's/:/-/')
			dirb "$line" "$jbossWL,$WORDLISTS" -r -o ${output}.txt
			unset line
		done

	FRONTPAGE=$(tac $FILE | awk -F "Server:</b> " 'c&&c--c;/FrontPage/{c=7}' | grep -iIohE 'https?://[^"]*' | cut -d"<" -f1 | sort -u)
	for line in $FRONTPAGE
		do
			echo $line
			output=$(echo ${line}|sed -e 's,http.*://,,g' -e 's/:/-/')
			dirb "$line" "$frontpageWL,$WORDLISTS" -r -o ${output}.txt
			unset line
		done

	COLDFUSION=$(tac $FILE | awk -F "Server:</b> " 'c&&c--c;/ColdFusion/{c=7}' | grep -iIohE 'https?://[^"]*' | cut -d"<" -f1 | sort -u)
	for line in $COLDFUSION
		do
			echo $line
			output=$(echo ${line}|sed -e 's,http.*://,,g' -e 's/:/-/')
			dirb "$line" "$coldfusionWL,$WORDLISTS" -r -o ${output}.txt
			unset line
		done

	SHAREPOINT=$(tac $FILE | awk -F "Server:</b> " 'c&&c--c;/SharePoint/{c=7}' | grep -iIohE 'https?://[^"]*' | cut -d"<" -f1 | sort -u)
	for line in $COLDFUSION
		do
			echo $line
			output=$(echo ${line}|sed -e 's,http.*://,,g' -e 's/:/-/')
			dirb "$line" "$sharepointWL,$WORDLISTS" -r -o ${output}.txt
			unset line
		done
}


function usage { 
	echo "Usage: $0 -r <Eyewitness report including path>" 
	echo "Usage: $0 -r <Eyewitness report including path> -w <Additional Wordlists. Separate with , >"
	1>&2; exit 1; 
}

if [ "$1" != "-r" ];then
	usage;
fi


while getopts ":r:w" opt
	do
		case $opt in
			r)
				FILE=$2
				if [ ! -f ${2} ]
					then
						echo
						echo "File ${2} does not exist. Exiting"
					exit 1
				fi
				;;
			w)
				WORDLISTS=$4
				if [ ! -f ${4} ]
					then
						echo
						echo "Wordlist ${4} does not exist. Exiting"
					exit 1
				fi
				;;
			\?)
				echo "Invalid option: -$OPTARG" >&2
				exit 1
				;;
			:)
				echo "Option -$OPTARG requires an argument." >&2
				exit 1
				;;
		esac
	done

main