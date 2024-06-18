#!/bin/bash
apt update
apt install -y moreutils
apt install -y snapd
apt install make gcc docker.io -y
apt install sudo -y
sudo apt install -y libcurl4-openssl-dev tar
sudo apt install -y libssl-dev sqlmap wget proxychains4
sudo apt install -y jq zip unzip
sudo apt install -y ruby-full
sudo apt install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt install -y build-essential libssl-dev libffi-dev python-dev
sudo apt install -y python3-setuptools
sudo apt install -y libldns-dev
sudo apt install python3-pip -y
sudo apt install -y python-pip
sudo apt install -y python3-dnspython
sudo apt install -y git
sudo apt install -y rename
sudo apt install -y xargs
sudo apt install -y chromium-l10n
sudo snap install chromium
sudo apt install -y golang
sudo apt install -y libpcap-dev
sudo apt install -y tmux
sudo apt install -y dnsutils
sudo apt install -y curl
#sudo apt install -y nmap
#sudo apt install -y dos2unix

pip3 install uro --break-system-packages
pip3 install requests --break-system-packages
pip3 install waymore --break-system-packages
pip3 install dirsearch --break-system-packages
pip3 install docker --break-system-packages
pip3 install --upgrade docker --break-system-packages

# Aquatone
mkdir /root/tools/aquatone_dir
cd /root/tools/aquatone_dir
latest_version_aquatone=$(curl -s https://api.github.com/repos/michenriksen/aquatone/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
download_link_aquatone="https://github.com/michenriksen/aquatone/releases/download/${latest_version_aquatone}/aquatone_linux_amd64_$(echo $latest_version_aquatone | tr -d 'v').zip"
curl -LO $download_link_aquatone
unzip /root/tools/aquatone_dir/*.zip
cp /root/tools/aquatone_dir/aquatone /usr/local/bin/aquatone
rm -rf /root/tools/aquatone_dir

# Install amass
cd /root/tools
curl -LO "https://github.com/owasp-amass/amass/releases/download/v3.23.3/amass_Linux_amd64.zip"
unzip amass_Linux_amd64.zip
cd /root/tools/amass_Linux_amd64
cp amass /usr/local/bin/amass

# Install massdns
git clone https://github.com/blechschmidt/massdns /root/tools/massdns
cd /root/tools/massdns
make
cp /root/tools/massdns/bin/massdns /usr/bin/massdns

#cd /root
#git clone https://github.com/projectdiscovery/nuclei-templates
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Fuzzing templates nuclei
git clone https://github.com/projectdiscovery/fuzzing-templates /root/tools/fuzzing-templates

# Install SecretFinder
#git clone https://github.com/m4ll0k/SecretFinder.git /root/tools/secretfinder
#cd /root/tools/secretfinder
#pip3 install -r requirements.txt --break-system-packages

# Install crlfuzz
curl -sSfL https://git.io/crlfuzz | sh -s -- -b /usr/local/bin

# Install Sublist3r
git clone https://github.com/aboul3la/Sublist3r /root/tools/SubList3r
cd /root/tools/SubList3r
pip3 install -r requirements.txt --break-system-packages

# Install corsy
git clone https://github.com/s0md3v/Corsy /root/tools/Corsy
cd /root/tools/Corsy
pip3 install -r requirements.txt --break-system-packages

# paramspider
git clone https://github.com/devanshbatham/paramspider /root/tools/Paramspider
cd /root/tools/Paramspider
mkdir domains
sed -i 's/results_dir = \"results\"/results_dir = \"\/root\/tools\/Paramspider\/domains\"/' /root/tools/Paramspider/paramspider/main.py
pip3 install . --break-system-packages

# Nuclei tech detect
cd /root/tools
wget https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/technologies/tech-detect.yaml

# GF-PATTERNS
mkdir /root/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /root/tools/Gf-Patterns
mv /root/tools/Gf-Patterns/*.json /root/.gf

# Custom scripts
#git clone https://github.com/R-s0n/Custom_Vuln_Scan_Templates /root/tools/Custom_Vuln_Scan_Templates

# Go packages
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/Emoe/kxss@latest
go install -v github.com/tomnomnom/anew@latest
go install github.com/takshal/freq@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/qsreplace@latest
#go install -v github.com/LukaSikic/subzy@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
#go install github.com/hahwul/dalfox/v2@latest
#go install github.com/KathanP19/Gxss@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
cp /root/go/bin/* /usr/local/bin/
nuclei -update-templates
cp /root/tools/ElKraken/Tools/doxycannon/proxychains.conf /etc/proxychains.conf

# Change firewall
iptables -A INPUT -p tcp --dport 1337 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 1337 -j DROP
sleep 2

# Start doxycannon
cd /root/tools/ElKraken/Tools/doxycannon
sleep 1
python3 doxycannon.py --build
sleep 5
tmux new-session -d -s doxycannon "python3 doxycannon.py --single"
sleep 5
