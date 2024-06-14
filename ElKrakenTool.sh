#!/bin/bash 
domain="$1"
proxy="socks5://127.0.0.1:1337"

mkdir -p /root/$domain/{vulns,wayback_data,httpx_info,subdomains,fuzzing,ports,aquatone,test_vulns}

echo "Subdomain enumeration on $domain" | notify -bulk -silent
python3 ~/tools/SubList3r/sublist3r.py -d $domain -o /root/$domain/subdomains/subdomains.txt
chaos -d $domain -silent | anew /root/$domain/subdomains/subdomains.txt
subfinder -d $domain -all -silent | anew /root/$domain/subdomains/subdomains.txt
assetfinder $domain --subs-only | grep "\.$domain$" | sed 's/*.//' | sort -u | anew /root/$domain/subdomains/subdomains.txt
amass enum -passive -norecursive -noalts -d $domain | grep "\.$domain$" | anew /root/$domain/subdomains/subdomains.txt
echo "$domain" | anew /root/$domain/subdomains/subdomains.txt
grep -v -f /root/tools/blacklist.txt /root/$domain/subdomains/subdomains.txt > /root/$domain/subdomains/subdomains_tmp.txt
mv /root/$domain/subdomains/subdomains_tmp.txt /root/$domain/subdomains/subdomains.txt
rm /root/$domain/subdomains/subdomains_tmp.txt

# Bruteforcing subdomains
echo -e "Bruteforcing dns with puredns on $domain"
puredns bruteforce -r /root/tools/massdns/lists/resolvers.txt /usr/share/seclists/Discovery/DNS/dns-Jhadix $domain --write puredns.txt
cat puredns.txt | anew /root/$domain/subdomains/subdomains.txt
rm puredns.txt

# Alive subdomains
echo "Getting alive subdomains on $domain" | notify -bulk -silent
httpx -l /root/$domain/subdomains/subdomains.txt -t 150 | tee -a /root/$domain/httpx_info/alive_subdomains.txt
echo -e "$(wc -l < /root/$domain/httpx_info/alive_subdomains.txt) alive subdomains on $domain" | notify -bulk -silent

# URLS
echo "Checking URLS with GAU on $domain" | notify -bulk -silent
cat /root/$domain/httpx_info/alive_subdomains.txt | gau --threads 15 --subs 2>/dev/null | tee -a /root/$domain/wayback_data/gau.txt
cat /root/$domain/httpx_info/alive_subdomains.txt | waybackurls | tee -a /root/$domain/wayback_data/waybackurls.txt
waymore -i $domain -mode U -oU /root/$domain/wayback_data/waymore.txt
cat /root/$domain/httpx_info/alive_subdomains.txt | katana -jc -d 5 -silent | tee -a /root/$domain/wayback_data/katana.txt

# Gf patterns
echo -e "Using GF for filter data on $domain" | notify -bulk -silent
cat /root/$domain/wayback_data/*.txt | gf xss | qsreplace 'FUZZ' | sort -u | tee -a /root/$domain/test_vulns/xss.txt
cat /root/$domain/wayback_data/*.txt | gf ssrf | qsreplace "$BURP_COLLABORATOR" | sort -u | tee -a /root/$domain/test_vulns/ssrf.txt
cat /root/$domain/wayback_data/*.txt | grep "=" | qsreplace 'FUZZ' | sort -u | httpx -silent | tee -a /root/$domain/test_vulns/params.txt

# Fuzzing templates
echo -e "Checking for multiple vulnerabilities" | notify -bulk -silent
nuclei -l /root/$domain/test_vulns/params.txt -p $proxy -t /root/tools/fuzzing-templates -o /root/$domain/vulns/fuzzing_templates.txt -rl 40 -c 10 -H "X-Forwarded-For: 127.0.0.1"

# Subdomain takeover 
echo -e "Checking for takeover with nuclei on $domain" | notify -bulk -silent
nuclei -t /root/nuclei-templates/takeovers -l /root/$domain/httpx_info/alive_subdomains.txt -p $proxy -o /root/$domain/vulns/takeovers.txt -H "X-Forwarded-For: 127.0.0.1"

# Nuclei Exposures
echo "Checking for Data exposure on $domain with nuclei" | notify -bulk -silent 
cat /root/$domain/wayback_data/gau.txt /root/$domain/wayback_data/katana.txt /root/$domain/wayback_data/waybackurls.txt /root/$domain/wayback_data/waymore.txt | grep -E "\.js$|\.json$" | sort -u | httpx -content-type | grep -E 'application/javascript|application/json' | awk '{print $1}' | tee -a /root/$domain/wayback_data/js-json.txt
nuclei -l /root/$domain/wayback_data/js-json.txt -t exposures -o /root/$domain/vulns/potential_secrets.txt -H "X-Hackerone: user" -H "X-Forwarded-For: 127.0.0.1"
echo -e "Nuclei secrets results -> $(wc -l < /root/$domain/vulns/potential_secrets.txt)" | notify -bulk -silent

# Nuclei Rs0n
echo "Checking with custom templates on $domain with nuclei" | notify -bulk -silent
nuclei -l /root/$domain/httpx_info/alive_subdomains.txt -p $proxy -t /root/tools/Custom_Vuln_Scan_Templates/Nuclei -o /root/$domain/vulns/nuclei_custom.txt -rl 3 -c 5 -H "X-Forwarded-For: 127.0.0.1"
echo -e "Nuclei Rs0n results number -> $(wc -l < /root/$domain/vulns/nuclei_custom.txt)" | notify -bulk -silent

# Dirsearch
dirsearch -w /root/tools/dirsearch/custom_wordlist.txt -t 50 -exclude 403,401,404,400 -H "X-Forwarded-For: 127.0.0.1" --proxy $proxy -l /root/$domain/httpx_info/alive_subdomains.txt --deep-recursive -R 4 --crawl --full-url  --no-color --format=csv -o /root/$domain/fuzzing/dirsearch.csv

# Running Corsy
echo "Running Corsy on $domain" | notify -bulk -silent
python3 ~/tools/Corsy/corsy.py -i /root/$domain/httpx_info/alive_subdomains.txt -o /root/$domain/vulns/cors.json
echo -e "Corsy results number -> $(cat /root/$domain/vulns/cors.json | grep 'high' | wc -l)" | notify -bulk -silent

# CRLFUZZ
echo "Running crlfuzz on $domain"  | notify -bulk -silent
crlfuzz -l /root/$domain/httpx_info/alive_subdomains.txt -o /root/$domain/vulns/crlf.txt
echo -e "crlfuzz results number -> $(wc -l < /root/$domain/vulns/crlf.txt)" | notify -bulk -silent

# Port scan
echo "Scanning ports with naabu on $domain" | notify -bulk -silent
cat /root/$domain/httpx_info/alive_subdomains.txt | dnsx -a -ro -silent | naabu -silent -top-ports 1000 -exclude-ports 80,443,21,22,110,143 -o /root/$domain/ports/naabu_ports.txt
echo -e "Naabu results number -> $(wc -l < /root/$domain/ports/naabu_ports.txt)" | notify -bulk -silent

# Screenshots
cat /root/$domain/httpx_info/alive_subdomains.txt | aquatone -chrome-path /snap/bin/chromium -out /root/$domain/aquatone
sleep 10

# Kill doxycannon after scan
tmux kill-session -t doxycannon
cd /root/tools/ElKraken/Tools/doxycannon
python3 doxycannon.py --down
docker rm $(docker ps -a -q)
docker rmi $(docker images -q)

echo "The scan has finished on $domain" | notify -bulk -silent

