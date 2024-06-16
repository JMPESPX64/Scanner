#!/bin/bash 

domain="$1"
proxy="socks5://127.0.0.1:1337"

# Subdomain enumeration
python3 ~/tools/SubList3r/sublist3r.py -d $domain -o /root/results/$domain/subdomains/subdomains.txt
chaos -d $domain -silent | grep "\.$domain$" | sed 's/*.//' | sort -u | anew /root/results/$domain/subdomains/subdomains.txt
subfinder -d $domain -all -silent | anew /root/results/$domain/subdomains/subdomains.txt
assetfinder $domain --subs-only | grep "\.$domain$" | sed 's/*.//' | sort -u | anew /root/results/$domain/subdomains/subdomains.txt
amass enum -passive -d $domain -noalts -norecursive | grep "\.$domain$" | sort -u | anew /root/results/$domain/subdomains/subdomains.txt

# Subdomain bruteforce (Puredns)
puredns -r /root/tools/massdns/lists/resolvers.txt /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt $domain --write puredns.txt
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

# Vulnerabilities

# XSS
cat /root/results/$domain/wayback_data/all-urls.txt | gf xss | qsreplace 'FUZZ' | sort -u | uro | Gxss -p TEST -o /root/results/$domain/test_vulns/XSS.txt
dalfox file /root/results/$domain/test_vulns/XSS.txt --waf-evasion --skip-mining-all --skip-headless -H "X-Forwarded-For: 127.0.0.1" --only-poc --proxy $proxy -o /root/results/$domain/vulns/XSS.txt

#LFI (Paramspider)

#SQLI

#SSRF

# Fuzzing

# Secrets
cat /root/results/$domain/wayback_data/*.txt | grep "\.js$" | sort -u | httpx -silent | nuclei -t exposures -o /root/results/$domain/vuls/exposures.txt
