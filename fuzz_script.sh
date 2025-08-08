WORDLIST="/usr/share/wordlists/dirb/common.txt"  # Adjust if needed

while read -r host; do
  echo "[*] Fuzzing directories on http://$host"
  gobuster dir -u "http://$host" -w "$WORDLIST" -o "gobuster_${host}.txt" -t 30 -q
done < live_webhosts.txt
