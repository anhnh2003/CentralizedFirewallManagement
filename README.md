# ✨ Quick Start 

## Get the code

```bash
$ git clone https://github.com/anhnh2003/CentralizedFirewallManagement
$ cd CentralizedFirewallManagement
```



<br />

## How to use it

```bash
$
$ # Virtualenv modules installation (Ubuntu systems)
$ python3 -m venv myenv
$ source myenv/bin/activate  # Activate it
$
$ # Install modules - SQLite Database
$ pip3 install -r requirements.txt
$

$ # Access the dashboard in browser: http://localhost:5000/
```

> Note: To use the app, please access the registration page and create a new user. After authentication, the app will unlock the private pages.

<br />

## ✨ Code-base structure

The project is coded using blueprints, app factory pattern, dual configuration profile (development and production), and an intuitive structure presented below:

```bash
< PROJECT ROOT >
   |
   |-- apps/
   |    |
   |    |-- home/                           # A simple app that serve HTML files
   |    |    |-- routes.py                  # Define app routes
   |    |
   |    |-- authentication/                 # Handles auth routes (login and register)
   |    |    |-- routes.py                  # Define authentication routes  
   |    |    |-- models.py                  # Defines models  
   |    |    |-- forms.py                   # Define auth forms (login and register) 
   |    |
   |    |-- static/
   |    |    |-- <css, JS, images>          # CSS files, Javascripts files
   |    |
   |    |-- templates/                      # Templates used to render pages
   |    |    |-- includes/                  # HTML chunks and components
   |    |    |    |-- navigation.html       # Top menu component
   |    |    |    |-- sidebar.html          # Sidebar component
   |    |    |    |-- footer.html           # App Footer
   |    |    |    |-- scripts.html          # Scripts common to all pages
   |    |    |
   |    |    |-- layouts/                   # Master pages
   |    |    |    |-- base-fullscreen.html  # Used by Authentication pages
   |    |    |    |-- base.html             # Used by common pages
   |    |    |
   |    |    |-- accounts/                  # Authentication pages
   |    |    |    |-- login.html            # Login page
   |    |    |    |-- register.html         # Register page
   |    |    |
   |    |    |-- home/                      # UI Kit Pages
   |    |         |-- index.html            # Index page
   |    |         |-- 404-page.html         # 404 page
   |    |         |-- *.html                # All other pages
   |    |    
   |  config.py                             # Set up the app
   |    __init__.py                         # Initialize the app
   |
   |-- requirements.txt                
   |
   |-- .env                                 # Inject Configuration via Environment
   |-- run.py                               # Start the app - WSGI gateway
   |
   |-- ************************************************************************
```

<br />
# 📚 Hướng dẫn cài đặt phpMyAdmin trên Ubuntu

![phpMyAdmin Logo](https://www.phpmyadmin.net/static/images/logo.png)

## 🎯 Mục tiêu

Hướng dẫn chi tiết cài đặt phpMyAdmin trên Ubuntu 20.04/22.04 kết hợp với LAMP Stack và các biện pháp bảo mật cơ bản.

## 📋 Điều kiện tiên quyết

- Máy chủ Ubuntu 20.04/22.04 LTS

- Quyền truy cập sudo hoặc root

- Kết nối Internet ổn định

- Đã cài đặt trình soạn thảo vi/nano

## 🚀 Cài đặt LAMP Stack

### 1. Cập nhật hệ thống

```bash

sudo apt update && sudo apt upgrade -y

sudo apt install software-properties-common -y

```

### 2. Cài đặt Apache Web Server

```bash

sudo apt install apache2 -y

```

**Kiểm tra hoạt động:**

```bash

sudo systemctl status apache2

# Output mong đợi: active (running)

```

Truy cập `http://<server-ip>` trên trình duyệt để xác nhận:

![Apache Welcome Page](https://example.com/apache-default-page.jpg)

### 3. Cài đặt MySQL Server

```bash

sudo apt install mysql-server -y

```

**Thiết lập bảo mật:**

```bash

sudo mysql_secure_installation

```

- Nhập mật khẩu root mới

- Chọn `Y` cho tất cả các tùy chọn bảo mật

- Xóa user anonymous

- Vô hiệu hóa đăng nhập root từ xa

- Xóa database test

### 4. Cài đặt PHP và Extensions

```bash

sudo apt install php libapache2-mod-php php-mysql \

php-mbstring php-zip php-gd php-json php-curl php-xml -y

```

**Kiểm tra phiên bản PHP:**

```bash

php -v

# PHP 8.1.x (hoặc phiên bản mới hơn)

```

**Khởi động lại Apache:**

```bash

sudo systemctl restart apache2

```

## 📦 Cài đặt phpMyAdmin

### 1. Cài đặt gói chính thức

```bash

sudo apt install phpmyadmin -y

```

**Lựa chọn trong quá trình cài đặt:**

- Chọn web server: **apache2** (Space để chọn)

- Cấu hình database tự động: **Yes**

- Nhập mật khẩu cho phpmyadmin database: **<your_secure_password>**

### 2. Kích hoạt các extension cần thiết

```bash

sudo phpenmod mbstring

sudo phpenmod xml

```

### 3. Tạo symbolic link (nếu cần)

```bash

sudo ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin

```

### 4. Kiểm tra cấu hình

```bash

sudo apache2ctl configtest

# Output mong đợi: Syntax OK

```

## 🔧 Cấu hình Nâng cao

### 1. Cấu hình Apache trên cổng 8080

**Chỉnh sửa file cấu hình:**

```bash

sudo nano /etc/apache2/ports.conf

```

Thêm dòng:

```apache

Listen 8080

```

**Mở firewall:**

```bash

sudo ufw allow 8080/tcp

```

### 2. Tạo Virtual Host

**Tạo file cấu hình:**

```bash

sudo nano /etc/apache2/sites-available/phpmyadmin.conf

```

**Nội dung mẫu:**

```apache

<VirtualHost *:8080>

ServerAdmin admin@example.com

ServerName pma.example.com

DocumentRoot /usr/share/phpmyadmin

<Directory /usr/share/phpmyadmin>

Options FollowSymLinks

DirectoryIndex index.php

AllowOverride All

Require all granted

</Directory>

ErrorLog ${APACHE_LOG_DIR}/phpmyadmin_error.log

CustomLog ${APACHE_LOG_DIR}/phpmyadmin_access.log combined

</VirtualHost>

```

**Kích hoạt Virtual Host:**

```bash

sudo a2ensite phpmyadmin.conf

sudo systemctl restart apache2

```

## 🔒 Thiết lập Bảo mật

### 1. Thay đổi URL truy cập

```bash

sudo mv /usr/share/phpmyadmin /usr/share/dbadmin-secure

```

### 2. Thiết lập HTTP Basic Auth

**Tạo file xác thực:**

```bash

sudo htpasswd -c /etc/apache2/.phpmyadmin-htpasswd admin-user

```

**Thêm vào cấu hình:**

```apache

<Directory /usr/share/phpmyadmin>

AuthType Basic

AuthName "Restricted Area"

AuthUserFile /etc/apache2/.phpmyadmin-htpasswd

Require valid-user

</Directory>

```

## � Truy cập phpMyAdmin

**URL:** `http://<server-ip>:8080` hoặc `http://pma.example.com:8080`

**Thông tin đăng nhập:**

- Username: `root` (MySQL root user)

- Password: Mật khẩu đã thiết lập trong `mysql_secure_installation`

![phpMyAdmin Login](https://example.com/pma-login-screen.jpg)

## 🛠 Khắc phục Sự cố Thường gặp

### 1. Lỗi 404 Not Found

```bash

# Kiểm tra symbolic link

sudo ls -l /var/www/html/phpmyadmin

# Khắc phục:

sudo ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin

sudo systemctl restart apache2

```

### 2. Lỗi "The mbstring extension is missing"

```bash

sudo apt install php-mbstring -y

sudo phpenmod mbstring

sudo systemctl restart apache2

```

### 3. Lỗi kết nối MySQL

```bash

# Kiểm tra trạng thái MySQL

sudo systemctl status mysql

# Đăng nhập bằng MySQL CLI

sudo mysql -u root -p

```

### 4. Lỗi phân quyền

```bash

# Sửa quyền thư mục

sudo chown -R www-data:www-data /usr/share/phpmyadmin

sudo chmod -R 755 /usr/share/phpmyadmin

```

## 🔄 Cập nhật phpMyAdmin

```bash

sudo apt update

sudo apt install --only-upgrade phpmyadmin -y

sudo systemctl restart apache2

```
---
## Setup log file for iptables
1. Tạo file log và cấp quyền
```bash
sudo touch /var/log/iptables.log
sudo chmod 644 /var/log/iptables.log
```
2. Cấu hình rsyslog để nhận log từ iptables
```bash
sudo nano /etc/rsyslog.d/10-iptables.conf
``` 
- Thêm nội dung sau: 
```bash
:msg,contains,"[IPTABLES] " -/var/log/iptables.log
& stop
```
- khởi động lại rsyslog
```bash
sudo systemctl restart rsyslog
``` 
- Thử thêm các rule ghi lại log vào iptables
```bash
sudo iptables -A INPUT -j LOG --log-prefix "[IPTABLES] INPUT: " --log-level 4
sudo iptables -A OUTPUT -j LOG --log-prefix "[IPTABLES] OUTPUT: " --log-level 4
sudo iptables -A FORWARD -j LOG --log-prefix "[IPTABLES] FORWARD: " --log-level 4
```
# 📚 Hướng dẫn cài đặt và cấu hình cho Nodes từ xa (Client Nodes)

Để ứng dụng quản lý tường lửa tập trung có thể thu thập log và trực quan hóa dữ liệu từ các node, mỗi node từ xa cần được cấu hình đúng cách để cho phép truy cập SSH và ghi log IPTables.

---

## 🎯 Mục tiêu trên mỗi Node

1.  **Thiết lập SSH Key-based Authentication:** Đảm bảo server quản lý có thể SSH vào node mà không cần mật khẩu.
2.  **Cấp quyền `sudo NOPASSWD` cho các lệnh cần thiết:** Cho phép user SSH đọc log và thêm/quản lý luật IPTables mà không cần nhập mật khẩu `sudo`.
3.  **Cài đặt các dependency cần thiết:** Đảm bảo các công cụ như `iptables-persistent` (để lưu luật) và `rsyslog` hoạt động.
4.  **Cấu hình luật ghi log IPTables:** Thêm các luật để IPTables ghi log vào `/var/log/iptables.log` trên cả ba chain `INPUT`, `OUTPUT`, `FORWARD`.

---

## 📋 Điều kiện tiên quyết trên mỗi Node

* Hệ điều hành Ubuntu 20.04/22.04 LTS (hoặc tương đương)
* Quyền truy cập `sudo` hoặc `root` ban đầu
* Kết nối Internet ổn định

---

## 🚀 Cài đặt và Cấu hình

### 1. Cập nhật hệ thống và cài đặt OpenSSH Server

Đảm bảo hệ thống được cập nhật và `openssh-server` đã được cài đặt để cho phép truy cập SSH.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
# 📚 Hướng dẫn cài đặt và cấu hình cho Nodes quản lí (Management Nodes)
## Start the app
```bash
gunicorn --bind 0.0.0.0:5000 run:app
```