#!/bin/bash
domain=$1
rootdir=$HOME/Pentest_Programs
PWD="$rootdir/$domain"


usage (){
    echo "./subdomain_enum_amass_subfinder.sh target"
}

if [[ $# -ne 1 ]]; then
    usage
    exit 1
fi

declare -a tools=("amass" "subfinder")

for tool in "${tools[@]}"
do
    if ! [ -x "$(command -v $tool)" ]; then
        echo "Please install all requirement tools for this scripts! Requirement tools: amass, subfinder, massdns, masscan, nmap, aquatone, jq, whatweb. Missing: $tool."
        exit 1
    fi
done

# amass + subfinder

# create destination directory
echo "Destination Directory: $PWD. Checking ..."
if [ -d "$rootdir/$domain" ]; then
    if [ "$(ls -A $rootdir/$domain)" ]; then
        echo "Directory $rootdir/$domain is not empty. Maybe previous result still exists."
    fi
else
    echo "Destination doesnot exists. Creating ..."
    mkdir $rootdir/$domain
fi
echo "Done!"

# amass
echo "> amass -src -ip -active -d $domain -o $PWD/hosts-amass.txt"
amass -src -ip -active -d $domain -o $PWD/hosts-amass.txt

# Subfinder with bruteforce option
echo "Starting BruteForce with subfinder ..."
echo "> subfinder -b -d $domain -nW -t 40 -w subdomains-top1mil-20000.txt -o $PWD/$domain.subfinder.bruteforce.txt"
subfinder -b -d $domain -nW -t 40 -w subdomains-top1mil-20000.txt -o "$PWD/$domain.subfinder.bruteforce.txt"

# get hosts
cat $PWD/hosts-amass.txt | cut -d']' -f 2 | awk '{print $1}' | sort -u > $PWD/$domain.amass.txt
rm $PWD/hosts-amass.txt

# Result Scrapping
cat $PWD/$domain.amass.txt $PWD/$domain.subfinder.bruteforce.txt | sort -u > $PWD/$domain.final.txt
