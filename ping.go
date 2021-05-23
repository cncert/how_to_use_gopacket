package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

type ICMP struct {
	Type        uint8
	Code        uint8
	CheckSum    uint16
	Identifier  uint16
	SequenceNum uint16
}

func usage() {
	msg := `
Need to run as root!

Usage:
	goping host

	Example: ./goping www.baidu.com`

	fmt.Println(msg)
	os.Exit(0)
}

func getICMP(seq uint16) ICMP {
	//构造ICMP报文
	icmp := ICMP{
		Type:        8,
		Code:        0,
		CheckSum:    0,
		Identifier:  0,
		SequenceNum: seq,
	}
	//利用binary可以把一个结构体数据按照指定的字节序读到缓冲区里面，计算校验和后，再读进去
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, icmp)
	icmp.CheckSum = CheckSum(buffer.Bytes())
	buffer.Reset()

	return icmp
}

func sendICMPRequest(icmp ICMP, destAddr *net.IPAddr) error {
	// 发送ICMP请求
	//net.DialIP表示生成一个IP报文，版本号是v4，协议是ICMP（这里字符串ip4:icmp会把IP报文的协议字段设为1表示ICMP协议）
	conn, err := net.DialIP("ip4:icmp", nil, destAddr)
	if err != nil {
		fmt.Printf("Fail to connect to remote host: %s\n", err)
		return err
	}
	defer conn.Close()

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, icmp)

	if _, err := conn.Write(buffer.Bytes()); err != nil {
		return err
	}

	tStart := time.Now()

	conn.SetReadDeadline((time.Now().Add(time.Second * 2)))

	recv := make([]byte, 1024)
	receiveCnt, err := conn.Read(recv)
	fmt.Println(recv)
	fmt.Println(string(recv[5]))
	if err != nil {
		return err
	}

	tEnd := time.Now()
	duration := tEnd.Sub(tStart).Nanoseconds() / 1e6

	fmt.Printf("%d bytes from %s: seq=%d time=%dms\n", receiveCnt, destAddr.String(), icmp.SequenceNum, duration)

	return err
}

func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}

func Ping() {
	if len(os.Args) < 2 {
		usage()
	}
	maxTime := 2
	host := os.Args[1] // 获取主机ip
	//目的地址raddr是一个URL，这里使用Resolve进行DNS解析，注意返回值是一个指针，
	//所以DialIP方法中, raddr参数没有取地址符
	raddr, err := net.ResolveIPAddr("ip", host)

	if err != nil {
		fmt.Printf("Fail to resolve %s, %s\n", host, err)
		return
	}

	fmt.Printf("Ping %s (%s):\n\n", raddr.String(), host)
	ticker := time.NewTicker(time.Second)
	for i := 1; i < maxTime; i++ {
		<-ticker.C
		if err = sendICMPRequest(getICMP(uint16(i)), raddr); err != nil {
			fmt.Printf("Error: %s\n", err)
		}
		// time.Sleep(1 * time.Second)

	}
	ticker.Stop()
}
