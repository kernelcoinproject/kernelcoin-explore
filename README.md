# kernelcoin-explore
Block Explorer hosted at https://explore.kernelcoin.org

## Screenshots
<img width="1380" height="817" alt="Screenshot 2025-11-18 at 8 14 13 PM" src="https://github.com/user-attachments/assets/457e9dae-d1c9-4ff1-b4df-1b5c9afae2f4" />

## Basic Setup

Get yourself a cloud hosted vm and connect via ssh

As non root user

1. Setup kernelcoind

```
mkdir -p kernelcoin
cd kernelcoin
wget https://github.com/kernelcoinproject/kernelcoin/releases/download/main/kernelcoin-0.21.4-x86_64-linux-gnu.tar.gz
tar xf kernelcoin-0.21.4-x86_64-linux-gnu.tar.gz
```

```
mkdir -p ~/.kernelcoin
cat > ~/.kernelcoin/kernelcoin.conf << EOF
# enable p2p
listen=1
txindex=1
logtimestamps=1
server=1
rpcuser=mike
rpcpassword=x
rpcport=9332
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
EOF
```

```
./kernelcoind
```

2. Download and run the website binary

```
sudo yum install golang
cd ~
git clone ...
cd kernelcoin-explore
go build
./kernelcoin-explore
```


3. Setup caddy to host via https without username and password

As root
```
mkdir -p /opt/caddy
cd /opt/caddy
wget https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_amd64.tar.gz
tar xf caddy_2.10.2_linux_amd64.tar.gz
```

```
DOMAIN="website.duckdns.org"
cat > /opt/caddy/Caddyfile << EOF
$DOMAIN {

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    encode gzip

    log {
        output file /var/log/caddy/wallet.log {
            roll_size 100mb
            roll_keep 5
        }
        format json
    }

    reverse_proxy 127.0.0.1:8080
}
EOF
/opt/caddy/caddy run
```

4. Run it all at boot via tmux

Run as root user (port 443 requires root)
```
yum install -y tmux cronie
cat > /root/startWeb.sh << EOF
tmux kill-session -t caddy 2>/dev/null
tmux new -s caddy -d
tmux send-keys -t caddy "cd /opt/caddy && ./caddy run" C-m
EOF
chmod +x /root/startWeb.sh
```

Run as root user
```
crontab -e
@reboot /root/startWeb.sh
```

Run as non-root user
```

cat > /home/ec2-user/start.sh << EOF
tmux kill-session -t block 2>/dev/null
tmux new -s block -d
tmux neww -t block -n kernelcoin
tmux neww -t block -n web
tmux send-keys -t block:kernelcoin "cd /home/ec2-user/kernelcoin && ./kernelcoind" C-m
tmux send-keys -t block:web "cd /home/ec2-user/kernelcoin-explore && ./kernelcoin-explore" C-m
EOF
chmod +x /home/ec2-user/startup.sh
```

Run as non-root user
```
crontab -e
@reboot /home/ec2-user/startup.sh
```


