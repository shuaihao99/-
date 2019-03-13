#!/usr/bin/env python3
# coding=UTF-8
'''
@Author: Hao
@Description: 根据指令,扫描指定的ip或网段
                使用nmap.PortScanner模块扫描,获取返回信息
                根据返回信息,筛选消息重新组合新的字典
                输出端口信息和操作系统信息
@Date: 2019-03-12 23:15:28
@LastEditTime: 2019-03-12 23:27:52
'''
from optparse import OptionParser
import time
from threading import Thread
import queue
import nmap
import sys
from IPy import IP  #计算网段内可用ip
q_data = queue.Queue()  #子线程数据队列

def inData():
    '''
    @description: 从脚本调用参数中,获取需要的参数
    @return: 返回ip列表
    '''
    usage = "./nmapOsScan.py <-i IPAddr> <-n Network/Netmask> <-f IPAddrFile>"
    parser = OptionParser(usage = usage)
    parser.add_option("-i" ,type = "string" ,dest = "IPAddr" ,help = "扫描单个ip地址")
    parser.add_option("-n" ,type = "string" ,dest = "Network" ,help = "扫描单个网段")
    parser.add_option("-f" ,type = "string" ,dest = "IPAddrFile" ,help = "扫描指定文件内所有ip")
    (options ,args) = parser.parse_args()
    IPAddr = options.IPAddr
    Network = options.Network
    IPAddrFile = options.IPAddrFile
    if (not IPAddr) and (not Network) and (not IPAddrFile) :
        parser.print_help()
        sys.exit()
    ip_list = []
    if IPAddr:
        ip_list.append(IPAddr)
    elif Network:
        temp_ip = IP(Network)      #调用IPy的IP计算模块,返回网段内所有ip迭代器
        for ip in temp_ip[1:-1]:   #去除网络位和广播位
            ip_list.append(str(ip))
    elif IPAddrFile:
        with open(IPAddrFile ,'r') as ip_file:
            for ip in ip_file:
                ip_list.append(ip.replace("\n","").replace("\r",""))    #去除换行符
    return ip_list

def scan(ipaddr):
    '''
    @description: 扫描子线程函数
    @param {type} 传入单个ip地址
    @return: 若该ip有数据,则put到q_data消息队列中
    '''
    nm = nmap.PortScanner()
    try:
        result = nm.scan(hosts = ipaddr ,arguments='-O')
        if result['nmap']['scanstats']['uphosts'] != '0':   #检测主机是否存活
            if 'ipv4' in result['scan'][ipaddr]['addresses'].keys(): #检测ip地址是否存在,防止错误
                ip = result['scan'][ipaddr]['addresses']['ipv4']
            else:
                ip = "None"
            if 'mac' in result['scan'][ipaddr]['addresses'].keys():  #检测mac地址是否存在
                mac = result['scan'][ipaddr]['addresses']['mac']
            else:
                mac = "None"
            if result['scan'][ipaddr]['osmatch']:                   #检测是否扫描到系统版本
                os = result['scan'][ipaddr]['osmatch'][0]['name']
            else:
                os = "None"
            ports = []
            if 'tcp' in result['scan'][ipaddr].keys():    #检测是否存在tcp端口
                if result['scan'][ipaddr]['tcp'] != {}:                 #且部位空字典
                    for open_port,port_data in result['scan'][ipaddr]['tcp'].items():
                        ports.append({open_port:port_data['name']})     #列表嵌套字典
                else:
                    ports = [{"None":"None"}]
            else:
                ports = [{"None":"None"}]
            re_dict = {"ip":ip ,"mac":mac ,"os":os ,"ports":ports}
            q_data.put(re_dict)
    except Exception as e:
        print(ipaddr + e)

def startScanThread(ip_list):
    '''
    @description: 启动扫描线程函数,扫描完成后,get q_data消息队列中所有字典,并添加到列表
    @param {type} 传入需扫描的ip地址列表
    @return: 返回扫描结果组成的列表
    '''
    thr_list = []
    for ip in ip_list:
        t = Thread(target=scan ,args=(ip,))
        t.start()
        time.sleep(0.05)
        thr_list.append(t)
    for t in thr_list:
        t.join()
    result = []
    while not q_data.empty():
        result.append(q_data.get())
    return result

def dataPrint(result):
    '''
    @description: 根据扫描结果组成的字典,输出数据
    @param {type} 传入所有ip扫描结果组成的列表
    '''
    sort_result = sorted(result ,key = lambda r:int(r['ip'].split('.')[-1]))
    for item in sort_result:
        print(30*"-")
        print(f"IP: {item['ip']}\tMAC: {item['mac']}")
        print(f"OS: {item['os']}")
        for port_data in item['ports']:
            for port,data in port_data.items():
                print(f"\t{port}\t{data}")
def main():
    '''
    @description: 主函数
    '''
    ip_list = inData()
    result = startScanThread(ip_list)
    dataPrint(result)
if __name__ == "__main__":
    main()