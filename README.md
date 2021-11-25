## 实验五：基于Scapy编写端口扫描器

### 实验目的

- 掌握网络扫描之端口状态探测的基本原理

### 实验环境

- python 3.7.0
- Scapy 2.4.4
- nmap 7.91

### 实验要求

- [x]  TCP connect scan / TCP stealth scan
- [x]  TCP Xmas scan / TCP fin scan / TCP null scan
- [x]  UDP scan
- [x]  上述每种扫描技术的实现测试均需要测试端口状态为：`开放`、`关闭` 和 `过滤` 状态时的程序执行结果
- [x]  提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- [x]  在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的
- [x]  （可选）复刻 `nmap` 的上述扫描技术实现的命令行参数开关（每种扫描测试一种状态，且后面专门用nmap进行了扫描实验）

### 实验原理及补充

#### 课本原理

> `TCP connect scan` 与 `TCP stealth scan` 都是先发送一个`S`，然后等待回应。如果有回应且标识为`RA`，说明目标端口处于关闭状态；如果有回应且标识为`SA`，说明目标端口处于开放状态。这时
>
> - `TCP connect scan`会回复一个RA，在完成三次握手的同时断开连接
> - `TCP stealth scan`只回复一个R，不完成三次握手，直接取消建立连接
>
> `TCP Xmas scan、TCP fin scan`及`TCP null scan`不涉及三次交互。它们都是先发送一个包，然后根据目标主机是否回复`R`来目标端口的状态。不同的是：
>
> - TCP Xmas scan发送的是`FPU`
> - TCP fin scan发送的是`F`
> - TCP null scan发送的包里没有设置任何flag
>
> UDP是无连接的协议，通过发送`UDP+port`得到的回复确定被扫描主机的状态。
>
> - Open：`no response / server responds to the client with a UDP packet`；
> - Closed：`ICMP error type 3 and code 3`
> - filtered：`no response / ICMP error type 3 and code 1,2,3,9,10,13`。

#### Kali端口命令

```shell
## 使用防火墙
#允许端口访问
sudo ufw enable && ufw allow portno/tcp(udp)
#停用端口访问
sudo ufw disable
#端口过滤
sudo ufw enable && sudo ufw deny 8888/tcp(udp)
## 使用iptables
# 允许端口访问
sudo iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
# 端口过滤
sudo iptables -A INPUT -p tcp --dport 8888 -j DROP
#指定端口监听
nc -l -p 8888
lsof -i 4 -L -P -n//查看处于监听状态的端口
```

#### 端口状态模拟

> - 关闭状态：对应端口没有开启监听, 防火墙没有开启。
>
>   ```shell
>   ufw disable
>   ```
>
> - 开启状态：对应端口开启监听: apache2基于TCP, 在80端口提供服务; DNS服务基于UDP,在53端口提供服务。防火墙处于关闭状态。
>
>   ```shell
>   systemctl start apache2 # port 80
>   systemctl start dnsmasq # port 53
>   ```
>
> - 过滤状态：对应端口开启监听, 防火墙开启。
>
>   ```shell
>   ufw enable && ufw deny 80/tcp
>   ufw enable && ufw deny 53/udp
>   ```

### 实验过程

#### 网络拓扑

![](img-c5/net.png)

| GateWay      | Kali-Attacker  | Kali-Victim    |
| ------------ | -------------- | -------------- |
| 172.16.111.1 | 172.16.111.111 | 172.16.111.137 |

- Attacker作为扫描端，Victim作为被扫描的靶机

#### TCP connect scan

- 攻击者向靶机发送SYN包，如果能完成三次握手（收到ACK），则端口为开放状态；
- 如果只收到一个RST包，则端口为关闭状态；
- 如果什么都没有收到，则端口为过滤状态。

##### 实验代码

```python
#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.137"
dst_port=8888

ret = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=0x2))
if ret is None:
    print("Filtered")
elif ret.haslayer(TCP):
    if ret[1].flags == 0x12:
        print("Open")
    elif ret[1].flags == 0x14:
        print("Closed")
```

##### Closed

- Attacker运行代码向靶机发送SYN包

  ![](img-c5/run_TCPconnect.png)

- 靶机上抓包

  ![](img-c5/cap_TCPconnect.png)

- 接收到RST/ACK数据包，说明8888端口处于关闭状态

  ![](img-c5/cap_RST_ACK.png)

- 用nmap复刻结果

  ![](img-c5/nmap_close.png)

##### Filtered

- 靶机端口过滤；Attacker运行代码发送包；靶机抓包

  ![](img-c5/cap_filter.png)

- 只接收到一个TCP包，说明端口处于过滤状态

  ![](img-c5/cap_TCP.png)

- 用nmap复刻结果

  ![](img-c5/nmap_filter.png)

##### Open

- 靶机删除先前过滤条件，同时开启监听

  ![](img-c5/cap_open.png)

- Attacker发送包

  ![](img-c5/run_TCP2.png)

- 抓包结果中有三个TCP包，是一个完整的握手过程，说明端口开启

  ![](img-c5/cap_TCP3.png)

- nmap复刻结果

  ![](img-c5/nmap_open.png)

#### TCP stealth scan

- 与connect scan相似，Attacker向靶机发送SYN包，如果端口开启，就会收到SYN/ACK响应包，但此时Attacker会向靶机发送RST数据包，来避免完成TCP三次握手，从而避免防火墙的探测；
- 如果端口关闭，Attacker会收到RST数据包；
- 如果端口处于过滤状态，则没有数据包返回，或者收到数据包的ICMP错误包，并显示不可达错误`type = 3 code 1,2,3,9,10,13`。

##### 实验代码

```python
#! /usr/bin/python

from scapy.all import *


def tcpstealthscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
    if (pkts is None):
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) /
                          TCP(dport=dst_port, flags="R"), timeout=10)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
        elif(pkts.haslayer(ICMP)):
            if(int(pkts.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("Filtered")


tcpstealthscan('172.16.111.137', 8888)
```

##### Closed

- ![](img-c5/run_TCPstl_clo.png)

- 发现靶机发送的数据报为RST/ACK数据包，说明端口关闭

  ![](img-c5/cap_TCP_stl.png)

- nmap复刻结果

  ![](img-c5/nmap_close_stl.png)

##### Filtered

- ![](img-c5/run_TCPstl_fil.png)

- 靶机只收到了一个TCP包，没有遇到发送错误ICMP包的情况，仍然可以说明端口是关闭的

  ![](img-c5/cap_fil_stl.png)

- ![](img-c5/nmap_filter_stl.png)

##### Open

- ![](img-c5/run_TCPstl_open.png)

- 靶机发送了SYN/ACK数据包，说明端口开启；靶机收到了Attacker发送的RST数据包，说明进行了SYN扫描

  ![](img-c5/cap_open_stl.png)

- ![](img-c5/nmap_open_stl.png)

#### TCP Xmas scan

- 在Xmas扫描中，Attacker发送的TCP数据包中设置PSH、FIN和URG位

  | Probe Response                                         | Assigned State |
  | ------------------------------------------------------ | -------------- |
  | No response received(even after retransmissions)       | open\|filtered |
  | TCP RST packet                                         | closed         |
  | ICMP unreachable error(type 3, code 1,2,3,9,10, or 13) | filtered       |

##### 实验代码

```python
#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.137"
dst_port=8888

ret = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=10)
if ret is None:
	print("Open|Filtered")
elif ret.haslayer(TCP):
	if ret[1].flags == 0x14:
		print("Closed")
elif ret.haslayer(ICMP):
	if int(ret[1].getlayer(ICMP).type)==3 and int(ret[1].getlayer(ICMP).code) in [1,2,3,9,10,13]:
		print("Filtered")
```

##### Closed

- ![](img-c5/run_TCPx_clo.png)

- Attacker发送了RST/ACK数据包，说明端口关闭

  ![](img-c5/cap_x_clo.png)

- ![](img-c5/nmap_close_xm.png)

##### Filtered

- ![](img-c5\run_TCPx_fil.png)

- 靶机只收到一个TCP包，没有响应，说明端口处于过滤或开启状态

  ![](img-c5\cap_x_fil.png)

- ![](img-c5\nmap_fil_xm.png)

##### Open

- ![](img-c5\run_TCPx_open.png)

- 靶机只收到一个TCP包，没有响应，说明端口处于过滤或开启状态

  ![](img-c5\cap_x_open.png)

- ![](img-c5\nmap_open_xm.png)

#### TCP fin scan

- 在Attacker发送TCP数据包时仅设置TCP FIN位；
- 端口判断与Xmas scan一致

##### 实验代码

```python
#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.137"
dst_port=8888

ret = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=10)
if ret is None:
	print("Open|Filtered")
elif ret.haslayer(TCP):
	if ret[1].flags == 0x14:
		print("Closed")
elif ret.haslayer(ICMP):
	if int(ret[1].getlayer(ICMP).type)==3 and int(ret[1].getlayer(ICMP).code) in [1,2,3,9,10,13]:
		print("Filtered")
```

##### Closed

- ![](img-c5\run_TCPfin_clo.png)

- Attacker发送了RST/ACK数据包，说明端口关闭

  ![](img-c5\cap_fin_clo.png)

- ![](img-c5\nmap_close_fin.png)

##### Filtered

- ![](img-c5\run_TCPfin_fil.png)

- 靶机只收到一个TCP包，并且没有响应，说明端口处于过滤或开启状态

  ![](img-c5\cap_fin_fil.png)

- ![](img-c5\nmap_fil_fin.png)

##### Open

- ![](img-c5\run_TCPfin_open.png)

- 靶机只收到一个TCP包，没有响应，说明端口处于过滤或开启状态

  ![](img-c5\cap_fin_open.png)

- ![](img-c5\nmap_open_fin.png)

#### TCP null scan

- 在Attacker发送TCP数据包时不设置任何位；
- 端口判断与Xmas scan一致

##### 实验代码

```python
#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.137"
dst_port=8888

ret = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=10)
if ret is None:
	print("Open|Filtered")
elif ret.haslayer(TCP):
	if ret[1].flags == 0x14:
		print("Closed")
elif ret.haslayer(ICMP):
	if int(ret[1].getlayer(ICMP).type)==3 and int(ret[1].getlayer(ICMP).code) in [1,2,3,9,10,13]:
		print("Filtered")
```

##### Closed

- ![](img-c5\run_TCPnull_clo.png)

- Attacker发送了RST/ACK包，说明端口关闭

  ![](img-c5\cap_cull_clo.png)

- ![](img-c5\nmap_close_null.png)

##### Filtered

- ![](img-c5\run_TCPnull_fil.png)

- 靶机只收到一个TCP包且没有响应，说明端口处于过滤或开启状态

  ![](img-c5\cap_null_fil.png)

- ![](img-c5\nmap_fil_null.png)

##### Open

- ![](img-c5\run_TCPnull_open.png)

- 靶机只收到一个TCP包且没有响应，说明端口处于过滤或开启状态

  ![](img-c5\cap_null_open.png)

- ![](img-c5\nmap_open_null.png)

#### UDP scan

- UDP是一种无连接的传输协议，不保证数据包一定到达目的地；
- Attacker收到来自靶机的UDP响应包时，说明端口开启；
- 同时若没有得到响应，端口也可能处于开启或过滤状态；
- 如果收到ICMP端口不可达错误，说明端口关闭；
- 如果收到其他ICMP错误，说明端口处于过滤状态

##### 实验代码

```python
#! /usr/bin/python

from scapy.all import *

dst_ip="172.16.111.137"
dst_port=53

pkt = IP(dst=dst_ip)/UDP(dport=dst_port)
ret = sr1(pkt,timeout=10)
if ret is None:
	print("Open|Filtered")
elif ret.haslayer(UDP):
	print("Open")
elif ret.haslayer(ICMP):
	if int(ret.getlayer(ICMP).type)==3 and int(ret.getlayer(ICMP).code)==3:
		print("Close")
	elif int(ret.getlayer(ICMP).type)==3 and int(ret.getlayer(ICMP).code) in [1,2,9,10,13]:
		print("Filtered")
elif ret.haslayer(IP) and ret.getlayer(IP).proto == 17:
        print("Open")
```

##### Closed

- ![](img-c5\run_UDP_clo.png)

- 靶机收到Attacker发送的UDP数据包，并发送了ICMP端口不可达的数据包，在ICMP数据中Type和code都为3，说明端口关闭

  ![](img-c5\cap_udp_clo.png)

- ![](img-c5\nmap_close_UDP.png)

##### Filtered

- ![](img-c5\run_UDP_fil.png)

- 靶机接收到Attacker发送的UDP数据包，但没有做出响应，说明端口处于过滤状态

  ![](img-c5\cap_udp_fil.png)

- ![](img-c5\nmap_fil_UDP.png)

##### Open

- 安装dnsmasq工具

  ![](img-c5\install_dnsmasq.png)

  开启端口

  ![](img-c5\dsn_allow_fil.png)

- 靶机接受了Attacker发送的UDP数据包并发送了响应包，说明端口开启

  ![](img-c5\cap_udp_open.png)

- ![](img-c5\nmap_open_UDP.png)

### 问题与解决

- 模拟窗口状态：检查工具是否安装`sudo apt install`
- nmap命令：偶尔报错，可能需要调整参数，更普遍的是提升权限`sudo nmap -sS -p`

### 参考资料

- [课本第五章](https://c4pr1c3.gitee.io/cuc-ns/chap0x05/main.html)
- [Linux kali开启端口、关闭防火墙](https://blog.csdn.net/qq_42103479/article/details/90111365)
- [Port Scanning Using Scapy](https://resources.infosecinstitute.com/port-scanning-using-scapy/)
- [scapy2.4.4文档](https://scapy.readthedocs.io/en/latest/)
- [吕九洋师哥的作业](https://github.com/CUCCS/2020-ns-public-LyuLumos/tree/ch0x05/ch0x05#udp-scan)

