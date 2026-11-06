# Ustack


#### dpdk虚拟机
```
完整虚拟机环境下载：
链接：https://pan.baidu.com/s/1qY7_bMgIuefF4Vf75o3nog 
提取码：g7on 

用户名：king
密码：123456
```
#### 搭建dpdk 虚拟机，参考课程视频讲解

```
代码编译
# export RTE_SDK=/home/king/share/dpdk/dpdk-stable-19.08.2
# export RTE_TARGET=x86_64-native-linux-gcc
# make
添加静态arp
# netsh -c i i add neighbors 7 192.168.146.136 00-0c-29-4b-c0-d5
删除静态arp
# netsh i i delete neighbors 7
#
```




            
            