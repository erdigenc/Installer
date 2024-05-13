#!/bin/bash

#################################################### CONFIGURATION ###
BUILD=1
PASS=$(openssl rand -base64 32|sha256sum|base64|head -c 32| tr '[:upper:]' '[:lower:]')
DBPASS=$(openssl rand -base64 24|sha256sum|base64|head -c 32| tr '[:upper:]' '[:lower:]')



####################################################   CLI TOOLS   ###
reset=$(tput sgr0)
bold=$(tput bold)
underline=$(tput smul)
black=$(tput setaf 0)
white=$(tput setaf 7)
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
purple=$(tput setaf 5)
bgblack=$(tput setab 0)
bgwhite=$(tput setab 7)
bgred=$(tput setab 1)
bggreen=$(tput setab 2)
bgyellow=$(tput setab 4)
bgblue=$(tput setab 4)
bgpurple=$(tput setab 5)



#################################################### YEĞİTEK KURULUM ######



# LOGO
clear
echo "${green}${bold}"
echo ""
echo "                  _     _                        "
echo "                 / \   / \                       "
echo "                                                 "
echo "__     ________ _____ _____ _______ ______ _  __ "
echo "\ \   / /  ____/ ____|_   _|__   __|  ____| |/ / "
echo " \ \_/ /| |__ | |  __  | |    | |  | |__  |   /  "
echo "  \   / |  __|| | |_ | | |    | |  |  __| |  |   "
echo "   | |  | |___| |__| |_| |_   | |  | |____|   \  "
echo "   |_|  |______\_____|_____|  |_|  |______|_|\_\ "
echo ""
echo "Yükleme işlemleri başlıyor lütfen bekleyin.!"
echo "${reset}"
sleep 3s

echo "Kurulmasını istediğiniz PHP sürümünü belirtiniz (Örn. 8.2):"
read VERSIONPHP
echo "Projenin hizmet vereceği domaini belirtiniz yok ise ip adresini yazınız (Örn. yegitek.meb.gov.tr veya 10.120.25.4):"
read DOMAIN
echo "Proje için bir kulllanıcı oluşturulacaktır bu kullanıcı için bir kullanıcı adı giriniz. (Örn. projeadi)"
read USERNAME

# OS CHECK
clear
clear
echo "${bggreen}${black}${bold}"
echo "İşletim sistemi kontrol ediliyor..."
echo "${reset}"
sleep 1s

ID=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
VERSION=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"')
if [ "$ID" = "ubuntu" ]; then
    case $VERSION in
        22.04)
            break
            ;;
        *)
            echo "${bgred}${white}${bold}"
            echo "Yeğitek kurulum aracı Linux Ubuntu 22.04 LTS ile çalışmaktadır."
            echo "${reset}"
            exit 1;
            break
            ;;
    esac
else
    echo "${bgred}${white}${bold}"
    echo "Yeğitek kurulum aracı Linux Ubuntu 22.04 LTS ile çalışmaktadır."
    echo "${reset}"
    exit 1
fi



# ROOT CHECK
clear
clear
echo "${bggreen}${black}${bold}"
echo "İzin kontrolleri gerçekleştiriliyor..."
echo "${reset}"
sleep 1s

if [ "$(id -u)" = "0" ]; then
    clear
else
    clear
    echo "${bgred}${white}${bold}"
    echo "Yeğitek kurulum aracını root olarak çalıştırmanız gerekmektedir."
    echo "${reset}"
    exit 1
fi



# BASIC SETUP
clear
clear
echo "${bggreen}${black}${bold}"
echo "Temel kurulumlar gerçekleştiriliyor..."
echo "${reset}"
sleep 1s

sudo apt-get update
sudo apt-get -y install software-properties-common curl wget nano vim rpl sed zip unzip openssl expect dirmngr apt-transport-https lsb-release ca-certificates dnsutils dos2unix zsh htop ffmpeg


# GET IP
clear
clear
echo "${bggreen}${black}${bold}"
echo "IP adresi tespit ediliyor..."
echo "${reset}"
sleep 1s

IP=$(curl -s https://checkip.amazonaws.com)


# MOTD WELCOME MESSAGE
clear
echo "${bggreen}${black}${bold}"
echo "Motd ayarları yapılıyor..."
echo "${reset}"
sleep 1s

WELCOME=/etc/motd
sudo touch $WELCOME
sudo cat > "$WELCOME" <<EOF
                  _     _
                 / \   / \

__     ________ _____ _____ _______ ______ _  __
\ \   / /  ____/ ____|_   _|__   __|  ____| |/ /
 \ \_/ /| |__ | |  __  | |    | |  | |__  |   /
  \   / |  __|| | |_ | | |    | |  |  __| |  |
   | |  | |___| |__| |_| |_   | |  | |____|   \
   |_|  |______\_____|_____|  |_|  |______|_|\_\

M.E.B. Yenilik ve Eğitim Teknolojileri Genel Müdürlüğü

EOF


# ALIAS
clear
echo "${bggreen}${black}${bold}"
echo "CLI konfügürasyonları ayarlanıyor..."
echo "${reset}"
sleep 1s

shopt -s expand_aliases
alias ll='ls -alF'



# YEĞİTEK DIRS
clear
echo "${bggreen}${black}${bold}"
echo "Yeğitek klasörleri hazırlanıyor..."
echo "${reset}"
sleep 1s

sudo mkdir /etc/$USERNAME/
sudo chmod o-r /etc/$USERNAME
sudo mkdir /var/$USERNAME/
sudo chmod o-r /var/$USERNAME



# USER
clear
echo "${bggreen}${black}${bold}"
echo "Yeğitek root kullanıcısı oluşturuluyor..."
echo "${reset}"
sleep 1s

sudo pam-auth-update --package
sudo mount -o remount,rw /
sudo chmod 640 /etc/shadow
sudo useradd -m -s /bin/bash $USERNAME
echo "$USERNAME:$PASS"|sudo chpasswd
sudo usermod -aG sudo $USERNAME


# NGINX
clear
echo "${bggreen}${black}${bold}"
echo "nginx kuruluyor..."
echo "${reset}"
sleep 1s

sudo apt-get -y install nginx-core
sudo systemctl start nginx.service
sudo rpl -i -w "http {" "http { limit_req_zone \$binary_remote_addr zone=one:10m rate=1r/s; fastcgi_read_timeout 300;" /etc/nginx/nginx.conf
sudo rpl -i -w "http {" "http { limit_req_zone \$binary_remote_addr zone=one:10m rate=1r/s; fastcgi_read_timeout 300;" /etc/nginx/nginx.conf
sudo systemctl enable nginx.service


# FIREWALL
clear
echo "${bggreen}${black}${bold}"
echo "fail2ban kuruluyor..."
echo "${reset}"
sleep 1s

sudo apt-get -y install fail2ban
JAIL=/etc/fail2ban/jail.local
sudo unlink JAIL
sudo touch $JAIL
sudo cat > "$JAIL" <<EOF
[DEFAULT]
bantime = 3600
banaction = iptables-multiport
[sshd]
enabled = true
logpath  = /var/log/auth.log
EOF
sudo systemctl restart fail2ban
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow "Nginx Full"


# PHP
clear
echo "${bggreen}${black}${bold}"
echo "PHP kuruluyor..."
echo "${reset}"
sleep 1s


sudo add-apt-repository -y ppa:ondrej/php
sudo apt-get update

sudo apt-get -y install php$VERSIONPHP-fpm
sudo apt-get -y install php$VERSIONPHP-common
sudo apt-get -y install php$VERSIONPHP-curl
sudo apt-get -y install php$VERSIONPHP-openssl
sudo apt-get -y install php$VERSIONPHP-bcmath
sudo apt-get -y install php$VERSIONPHP-mbstring
sudo apt-get -y install php$VERSIONPHP-tokenizer
sudo apt-get -y install php$VERSIONPHP-mysql
sudo apt-get -y install php$VERSIONPHP-sqlite3
sudo apt-get -y install php$VERSIONPHP-pgsql
sudo apt-get -y install php$VERSIONPHP-redis
sudo apt-get -y install php$VERSIONPHP-memcached
sudo apt-get -y install php$VERSIONPHP-json
sudo apt-get -y install php$VERSIONPHP-zip
sudo apt-get -y install php$VERSIONPHP-xml
sudo apt-get -y install php$VERSIONPHP-soap
sudo apt-get -y install php$VERSIONPHP-gd
sudo apt-get -y install php$VERSIONPHP-imagick
sudo apt-get -y install php$VERSIONPHP-fileinfo
sudo apt-get -y install php$VERSIONPHP-imap
sudo apt-get -y install php$VERSIONPHP-cli
PHPINI=/etc/php/$VERSIONPHP/fpm/conf.d/$USERNAME.ini
sudo touch $PHPINI
sudo cat > "$PHPINI" <<EOF
memory_limit = 256M
upload_max_filesize = 256M
post_max_size = 256M
max_execution_time = 180
max_input_time = 180
EOF
sudo service php$VERSIONPHP-fpm restart


# PHP CLI
clear
echo "${bggreen}${black}${bold}"
echo "PHP CLI ayarlanıyor..."
echo "${reset}"
sleep 1s

sudo update-alternatives --set php /usr/bin/php$VERSIONPHP

# COMPOSER
clear
echo "${bggreen}${black}${bold}"
echo "Composer kuruluyor..."
echo "${reset}"
sleep 1s

php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --no-interaction
php -r "unlink('composer-setup.php');"
mv composer.phar /usr/local/bin/composer
composer config --global repo.packagist composer https://packagist.org --no-interaction


# GIT
clear
echo "${bggreen}${black}${bold}"
echo "GIT kuruluyor..."
echo "${reset}"
sleep 1s

sudo apt-get -y install git
sudo ssh-keygen -t rsa -C "git@github.com" -f /etc/$USERNAME/github -q -P ""


# DEFAULT VHOST
clear
echo "${bggreen}${black}${bold}"
echo "Vhost ayarlanıyor..."
echo "${reset}"
sleep 1s

NGINX=/etc/nginx/sites-available/default
if test -f "$NGINX"; then
    sudo unlink $NGINX
fi
sudo touch $NGINX
sudo cat > "$NGINX" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN;
    root /var/www/html;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    client_body_timeout 10s;
    client_header_timeout 10s;
    client_max_body_size 256M;
    index index.html index.php;
    charset utf-8;
    server_tokens off;
    location / {
        try_files   \$uri     \$uri/  /index.php?\$query_string;
    }
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
    error_page 404 /index.php;
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/$VERSIONPHP-fpm.sock;
    }
    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOF
sudo mkdir /etc/nginx/$USERNAME/
sudo systemctl restart nginx.service





# MYSQL
clear
echo "${bggreen}${black}${bold}"
echo "MySQL kuruluyor..."
echo "${reset}"
sleep 1s


sudo apt-get install -y mysql-server
SECURE_MYSQL=$(expect -c "
set timeout 10
spawn mysql_secure_installation
expect \"Press y|Y for Yes, any other key for No:\"
send \"n\r\"
expect \"New password:\"
send \"$DBPASS\r\"
expect \"Re-enter new password:\"
send \"$DBPASS\r\"
expect \"Remove anonymous users? (Press y|Y for Yes, any other key for No)\"
send \"y\r\"
expect \"Disallow root login remotely? (Press y|Y for Yes, any other key for No)\"
send \"n\r\"
expect \"Remove test database and access to it? (Press y|Y for Yes, any other key for No)\"
send \"y\r\"
expect \"Reload privilege tables now? (Press y|Y for Yes, any other key for No) \"
send \"y\r\"
expect eof
")
echo "$SECURE_MYSQL"
/usr/bin/mysql -u root -p$DBPASS <<EOF
use mysql;
CREATE USER '$USERNAME'@'%' IDENTIFIED WITH mysql_native_password BY '$DBPASS';
GRANT ALL PRIVILEGES ON *.* TO '$USERNAME'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF


# NODEJS
clear
echo "${bggreen}${black}${bold}"
echo "Node/npm kuruluyor..."
echo "${reset}"
sleep 1s

curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | sudo apt-key add -
curl -sL https://deb.nodesource.com/setup16.x | sudo -E bash -
NODE=/etc/apt/sources.list.d/nodesource.list
sudo unlink NODE
sudo touch $NODE
sudo cat > "$NODE" <<EOF
deb https://deb.nodesource.com/node_16.x focal main
deb-src https://deb.nodesource.com/node_16.x focal main
EOF
sudo apt-get update
sudo apt -y install nodejs
sudo apt -y install npm


# SON ADIMLAR
clear
echo "${bggreen}${black}${bold}"
echo "Son adımlar..."
echo "${reset}"
sleep 1s

sudo chown www-data:$USERNAME -R /var/www/html
sudo chmod -R 750 /var/www/html
sudo echo 'DefaultStartLimitIntervalSec=1s' >> /usr/lib/systemd/system/user@.service
sudo echo 'DefaultStartLimitBurst=50' >> /usr/lib/systemd/system/user@.service
sudo echo 'StartLimitBurst=0' >> /usr/lib/systemd/system/user@.service
sudo systemctl daemon-reload

#ŞABLON YÜKLENİYOR
clear
echo "${bggreen}${black}${bold}"
echo "Şablon yükleniyor..."
echo "${reset}"
sleep 1s
WEBPATH=/var/www/html/index.html
if test -f "$WEBPATH"; then
    sudo unlink WEBPATH
fi
sudo touch $WEBPATH
sudo cat > "$WEBPATH" <<EOF
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YEĞİTEK</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            background-color: #f0f0f0;
        }
        .logo {
            font-size: 100px;
            font-weight: bold;
            color: #333;
            margin-top: 100px;
        }
        .status {
            font-size: 50px;
            color: #666;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="logo">
        T.C. <br>
        Milli Eğitim Bakanlığı<br>
        Yenilik ve Eğitim Teknolojileri<br>
        Genel Müdürlüğü
    </div>
    <div class="status">
        <br>
        <br>
        <br>
        Bu proje yapım aşamasındadır.
    </div>
</body>
</html>

EOF

sudo systemctl restart nginx.service
sudo rpl -i -w "#PasswordAuthentication" "PasswordAuthentication" /etc/ssh/sshd_config
sudo rpl -i -w "# PasswordAuthentication" "PasswordAuthentication" /etc/ssh/sshd_config
sudo rpl -i -w "PasswordAuthentication no" "PasswordAuthentication yes" /etc/ssh/sshd_config
sudo rpl -i -w "PermitRootLogin yes" "PermitRootLogin no" /etc/ssh/sshd_config
sudo service sshd restart

# BİTİRİŞ
clear
echo "${bggreen}${black}${bold}"
echo "Kurulum sonlandırılıyor..."
echo "${reset}"
sleep 1s

# KURULUM TAMAMLANDI
clear
echo "***********************************************************"
echo "                    Kurulum Tamamlandı                     "
echo "***********************************************************"
echo ""
echo " SSH root user: $USERNAME"
echo " SSH root pass: $PASS"
echo " MySQL root user: $USERNAME"
echo " MySQL root pass: $DBPASS"
echo ""
echo " Sayfay görüntülemek için: http://$DOMAIN"
echo ""
echo "***********************************************************"
echo "             Bu bilgileri kaydetmeyi unutmayın!            "
echo "***********************************************************"