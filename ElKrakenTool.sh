#!/bin/bash

domain="$1"
proxy="socks5://127.0.0.1:1337"

mkdir -p /root/results/$domain/{httpx_info,subdomains,fuzzing,vulns,ports,wayback_data,aquatone}

alive_subdomains_path="/root/results/$domain/httpx_info/alive_subdomains.txt"
wayback_data_path="/root/results/$domain/wayback_data"
vulns_path="/root/results/$domain/vulns"
param_spider_path="/root/Paramspider/domains"
wordlist_dir="/root/tools/ElKraken/Tools/custom_wordlist.txt"

echo "Listing subdomains on $domain" | notify -bulk -silent
python3 /root/tools/SubList3r/sublist3r.py -d $domain -o /root/results/$domain/subdomains/subdomains.txt
subfinder -d $domain -all -silent | anew /root/results/$domain/subdomains/subdomains.txt
chaos -d $domain -silent | grep "\.$domain$" | sed 's/*.//' | anew /root/results/$domain/subdomains/subdomains.txt
assetfinder --subs-only $domain | grep "\.$domain$" | sed 's/*.//' | anew /root/results/$domain/subdomains/subdomains.txt
amass -passive -d $domain -noalts -norecursive | anew /root/results/$domain/subdomains/subdomains.txt
echo "Total passive subdomains found on $domain -> $(wc -l < /root/results/$domain/subdomains/subdomains.txt)" | notify -bulk -silent

# Bruteforce
echo "Bruteforce with puredns on $domain" | notify -bulk -silent
puredns bruteforce -r /root/tools/ElKraken/Tools/resolvers.txt /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt $domain --write puredns.txt
cat puredns.txt | anew /root/results/$domain/subdomains/subdomains.txt
echo "Total subdomains after run puredns on $domain -> $(wc -l < /root/results/$domain/subdomains/subdomains.txt)" | notify -bulk -silent

# Alive subdomains
echo "Running httpx on $domain" | notify -bulk -silent
httpx -l /root/results/$domain/subdomains/subdomains.txt -silent | tee -a /root/results/$domain/httpx_info/alive_subdomains.txt
echo -e "Alive subdomains $(wc -l < $alive_subdomains_path)" | notify -bulk -silent

# Wayback Data
echo "Wayback Data on $domain" | notify -bulk -silent
cat $alive_subdomains_path | gau --threads 16 --subs --blacklist jpg,png,woff,woff2,ico,svg,gif,jpeg | tee -a $wayback_data_path/gau.txt
cat $alive_subdomains_path | waybackurls | tee -a $wayback_data_path/waybackurls.txt
waymore -i $domain -mode U -oU $wayback_data_path/waymore.txt
cat $alive_subdomains_path | katana -jc -d 5 -silent | tee -a $wayback_data_path/katana.txt
paramspider -l $alive_subdomains_path

# ----------------------------------------------------------------- Vulnerabilities ------------------------------------------------------------------------------------

