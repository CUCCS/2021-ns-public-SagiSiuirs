## 实验五：基于Scapy编写端口扫描器

### 实验目的

- 掌握网络扫描之端口状态探测的基本原理

### 实验环境

- python 3.7.0
- Scapy 2.4.4
- nmap 7.91

### 实验要求

- [ ]  TCP connect scan / TCP stealth scan
- [ ]  TCP Xmas scan / TCP fin scan / TCP null scan
- [ ]  UDP scan
- [ ]  上述每种扫描技术的实现测试均需要测试端口状态为：`开放`、`关闭` 和 `过滤` 状态时的程序执行结果
- [ ]  提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- [ ]  在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的
- [ ]  （可选）复刻 `nmap` 的上述扫描技术实现的命令行参数开关（每种扫描测试一种状态，且后面专门用nmap进行了扫描实验）

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

#### Scapy基础

```shell
# 导入模块
from scapy.all import *
# 查看包信息
pkt = IP(dst="")
ls(pkt)
pkt.show()
summary(pkt)
# 发送数据包
send(pkt)  # 发送第三层数据包，但不会受到返回的结果。
sr(pkt)  # 发送第三层数据包，返回两个结果，分别是接收到响应的数据包和未收到响应的数据包。
sr1(pkt)  # 发送第三层数据包，仅仅返回接收到响应的数据包。
sendp(pkt)  # 发送第二层数据包。
srp(pkt)  # 发送第二层数据包，并等待响应。
srp1(pkt)  # 发送第二层数据包，并返回响应的数据包
# 监听网卡
sniff(iface="wlan1",count=100,filter="tcp")
# 应用：简单的SYN端口扫描 （测试中）
pkt = IP("...")/TCP(dport=[n for n in range(22, 3389)], flags="S")
ans, uans = sr(pkt)
ans.summary() # flag为SA表示开放，RA表示关闭
```

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



### 参考资料

- [课本第五章](https://c4pr1c3.gitee.io/cuc-ns/chap0x05/main.html)

