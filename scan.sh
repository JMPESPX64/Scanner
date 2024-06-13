#/bin/bash
input="$1"
while read -u 10 line;
do
bash ~/tools/ElKraken/ElKrakenTool.sh $line
sleep 3
done 10< "${1}"
