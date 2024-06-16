#!/bin/bash 

domain="$1"
proxy="socks5://127.0.0.1:1337"

# Subdomain enumeration
echo -e "Listing subdomains on $domain" | notify -bulk -silent
python3 ~/tools/SubList3r/sublist3r.py -d $domain -o /root/results/$domain/subdomains/subdomains.txt
chaos -d $domain -silent | grep "\.$domain$" | sed 's/*.//' | sort -u | anew /root/results/$domain/subdomains/subdomains.txt
subfinder -d $domain -all -silent | anew /root/results/$domain/subdomains/subdomains.txt
assetfinder $domain --subs-only | grep "\.$domain$" | sed 's/*.//' | sort -u | anew /root/results/$domain/subdomains/subdomains.txt
amass enum -passive -d $domain -noalts -norecursive | grep "\.$domain$" | sort -u | anew /root/results/$domain/subdomains/subdomains.txt
echo "$domain" | anew /root/results/$domain/subdomains/subdomains.txt

# Subdomain bruteforce (Puredns)
echo -e "Brute force with puredns on $domain" | notify -bulk -silent
puredns -r /root/tools/ElKraken/Tools/resolvers.txt /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt $domain --write puredns.txt
cat puredns.txt | anew /root/results/$domain/subdomains/subdomains.txt
rm puredns.txt
grep -v -f /root/tools/blacklist.txt /root/results/$domain/subdomains/subdomains.txt | sponge /root/results/$domain/subdomains/subdomains.txt

# Alive subdomains
httpx -l /root/results/$domain/subdomains/subdomains.txt -t 100 -silent | tee -a /root/results/$domain/httpx_output/alive_subdomains.txt

# Wayback Data
cat /root/results/$domain/httpx_output/alive_subdomains.txt | gau --threads 16 --subs --blacklist png,jpg,jpeg,gif,woff,woff2,ico,svg | tee -a /root/results/$domain/wayback_data/gau.txt
cat /root/results/$domain/httpx_output/alive_subdomains.txt | waybackurls | tee -a /root/results/$domain/wayback_data/waybackurls.txt
waymore -i $domain -mode U -oU /root/results/$domain/wayback_data/waymore.txt
cat /root/results/$domain/httpx_output/alive_subdomains.txt | katana -jc -d 5 -ef png,jpg,jpeg,gif,woff,woff2,ico,svg | tee -a /root/results/$domain/wayback_data/katana.txt
grep -v -f /root/tools/blacklist.txt /root/results/$domain/wayback_data/*.txt | tee -a /root/results/$domain/wayback_data/all-urls.txt

# Php endpoints
echo -e "Getting PHP endpoints on $domain" | notify -bulk -silent
cat /root/results/$domain/wayback_data/all-urls.txt | grep "\.php$" | httpx -silent | anew /root/results/$domain/fuzzing/php-endpoints.txt
echo -e "Total of PHP endpoints -> $(wc -l < /root/results/$domain/fuzzing/php-endpoints)" | notify -bulk -silent

# Vulnerabilities

# XSS
echo -e "Running dalfox on $domain" | notify -bulk -silent
cat /root/results/$domain/wayback_data/all-urls.txt | gf xss | uro | Gxss -p FUZZ -o /root/results/$domain/test_vulns/XSS.txt
dalfox file /root/results/$domain/test_vulns/XSS.txt --waf-evasion --skip-mining-all --skip-headless -H "X-Forwarded-For: 127.0.0.1" --only-poc --proxy $proxy -o /root/results/$domain/vulns/XSS.txt
echo -e "The dalfox scan have finished -> $(wc -l < /root/results/$domain/vulns/XSS.txt) results"

# Secrets
echo "Listing secrets with nuclei on $domain" | notify -bulk -silent
cat /root/results/$domain/wayback_data/all-urls.txt | grep "\.js$" | sort -u | httpx -silent | nuclei -t exposures -o /root/results/$domain/vulns/exposures.txt
echo -e "Nuclei (secrets) has finished -> $(wc -l < /root/results/$domain/vulns/exposures.txt)" | notify -bulk -silent

#LFI (Paramspider)
#cat /root/results/$domain/wayback_data/all-urls.txt | gf lfi | qsreplace 'FUZZ' | anew lfi-tmp.txt
#ffuf -w /root/tools/lfi-wordlist.txt 

#SQLI

#SSRF

# Subdomain takeover

# Fuzzing
