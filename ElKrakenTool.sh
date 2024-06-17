#!/bin/bash 

domain="$1"
proxy="socks5://127.0.0.1:1337"

mkdir -p /root/results/$domain/{wayback_data,vulns,ports,aquatone,subdomains,httpx_info,fuzzing,technologies,test_vulns}

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
puredns bruteforce -r /root/tools/ElKraken/Tools/resolvers.txt /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt $domain --write puredns.txt
cat puredns.txt | anew /root/results/$domain/subdomains/subdomains.txt
grep -v -f /root/tools/blacklist.txt /root/results/$domain/subdomains/subdomains.txt | sponge /root/results/$domain/subdomains/subdomains.txt

# Alive subdomains
echo "Running httpx on $domain" | notify -bulk -silent
httpx -l /root/results/$domain/subdomains/subdomains.txt -t 100 -silent | tee -a /root/results/$domain/httpx_info/alive_subdomains.txt
echo "$(wc -l < /root/results/$domain/httpx_info/alive_subdomains.txt) Alive subdomains" | notify -bulk -silent

# Wayback Data
echo "Listing URLS with mutliple tools (Archive.org + KATANA)" | notify -bulk -silent
cat /root/results/$domain/httpx_info/alive_subdomains.txt | gau --threads 16 --subs --blacklist png,jpg,jpeg,gif,woff,woff2,ico,svg | tee -a /root/results/$domain/wayback_data/gau.txt
cat /root/results/$domain/httpx_info/alive_subdomains.txt | waybackurls | tee -a /root/results/$domain/wayback_data/waybackurls.txt
waymore -i $domain -mode U -oU /root/results/$domain/wayback_data/waymore.txt
cat /root/results/$domain/httpx_info/alive_subdomains.txt | katana -jc -d 5 -ef png,jpg,jpeg,gif,woff,woff2,ico,svg | tee -a /root/results/$domain/wayback_data/katana.txt
paramspider -l /root/results/$domain/httpx_info/alive_subdomains.txt
grep -v -f /root/tools/blacklist.txt /root/results/$domain/wayback_data/*.txt | anew /root/results/$domain/wayback_data/all-urls.txt
cat /root/tools/Paramspider/domains/*.txt | anew /root/results/$domain/wayback_data/all-urls.txt

# PHP endpoints
echo -e "Getting PHP endpoints on $domain" | notify -bulk -silent
cat /root/results/$domain/wayback_data/all-urls.txt | grep -E "\.php" | sort -u | httpx -silent | anew /root/results/$domain/fuzzing/php-endpoints.txt
echo -e "Total of PHP endpoints -> $(wc -l < /root/results/$domain/fuzzing/php-endpoints)" | notify -bulk -silent

# XSS
echo -e "Running dalfox on $domain" | notify -bulk -silent
cat /root/results/$domain/wayback_data/all-urls.txt | gf xss | uro | Gxss -p FUZZ -o /root/results/$domain/test_vulns/XSS.txt
dalfox file /root/results/$domain/test_vulns/XSS.txt --waf-evasion --skip-mining-all --skip-headless -H "X-Forwarded-For: 127.0.0.1" --only-poc --proxy $proxy -o /root/results/$domain/vulns/XSS.txt
echo -e "The dalfox scan have finished -> $(wc -l < /root/results/$domain/vulns/XSS.txt) results"

# Secrets
echo "Listing secrets with nuclei on $domain" | notify -bulk -silent
cat /root/results/$domain/wayback_data/all-urls.txt | grep "\.js$" | sort -u | httpx -silent | nuclei -t exposures -H "X-Forwarded-For: 127.0.0.1" -o /root/results/$domain/vulns/exposures.txt
echo -e "Nuclei (secrets) has finished -> $(wc -l < /root/results/$domain/vulns/exposures.txt)" | notify -bulk -silent

# Subdomain takeover (Nuclei)
echo "Subdomain takeover with nuclei on $domain" | notify -bulk -silent
cat /root/results/$domain/httpx_info/alive_subdomains.txt | nuclei -t exposures -H "X-Forwarded-For: 127.0.0.1" -rl 40 -c 10 -o /root/results/$domain/vulns/takeovers.txt
echo "Takeovers -> $(wc -l < /root/results/$domain/vulns/takeovers.txt)" | notify -bulk -silent

# Lfi -> (Test with burpsuite)

# SQLI
echo -e "Listing sql injections on $domain" | notify -bulk -silent
cat /root/results/$domain/wayback_data/all-urls.txt | gf sqli | qsreplace 'FUZZ' | uro | tee -a sqli.tmp
sqlmap -m sqli.tmp --dbs --proxy=$proxy --batch --headers="X-Forwarded-For: 127.0.0.1" --risk 2 --level 3 --delay=0.5 | tee -a /root/results/$domain/vulns/sql_injection.txt
echo -e "SQLMAP has finished -> $(wc -l < /root/results/$domain/vulns/sql_injection.txt)" | notify -bulk -silent
rm sqli.tmp

# Port scan
echo -e "Scanning ports with naabu on $domain" | notify -bulk -silent
cat /root/results/$domain/httpx_info/alive_subdomains.txt | dnsx -a -ro | naabu -silent -top-ports 1000 -exclude-ports 80,443,21,22,25 -o /root/results/$domain/ports/naabu_ports.txt
echo -e "Naabu has finished on $domain -> $(wc -l < /root/results/$domain/ports/naabu_ports.txt)" | notify -bulk -silent

# Nuclei tech detect
echo -e "Running Nuclei for tech detect on $domain" | notify -bulk -silent
cat /root/results/$domain/httpx_info/alive_subdomains.txt | nuclei -t /root/tools/tech-detect.yaml -rl 40 -c 20 -o /root/results/$domain/technologies/nuclei_scan.txt

# Dirsearch
echo -e "Running dirsearch on $domain" | notify -bulk -silent
dirsearch -w /root/tools/ElKraken/Tools/custom_wordlist.txt -l /root/results/$domain/httpx_info/alive_subdomains.txt --proxy=$proxy -t 40 -exclude 403,401,404,400 -o /root/results/$domain/fuzzing/dirsearch.txt
echo -e "Dirsearch has finished on $domain -> $(wc -l < /root/results/$domain/fuzzing/dirsearch.txt) results" | notify -bulk silent

# Corsy
echo "Running Corsy on $domain" | notify -bulk -silent
python3 /root/tools/Corsy/corsy.py -i /root/results/$domain/httpx_info/alive_subdomains.txt -o /root/results/$domain/vulns/cors.json

# CRLFUZZ 
echo "Running crlfuzz on $domain" | notify -bulk -silent
crlfuzz -l /root/results/$domain/httpx_info/alive_subdomains.txt -o /root/results/$domain/vulns/crlf.txt

# Screenshots
echo "Taking screenshots on $domain" | notify -bulk -silent
cat /root/results/$domain/httpx_info/alive_subdomains.txt | aquatone -chrome-path /snap/bin/chromium -out /root/results/$domain/aquatone
echo "The scan has finished on $domain"

if [ "$(tail -n 1 /root/tools/domains.txt)" == "$domain" ] ; then 
  cd /root/tools/ElKraken/Tools/doxycannon
  python3 doxycannon.py --down
  sleep 1
  docker rm $(docker ps -a -q)
  docker rmi $(docker images -q)
else
  echo ""
fi
