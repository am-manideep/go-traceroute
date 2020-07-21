package main

import (
	"bufio"
	"context"
	"fmt"
	"go-traceroute/traceroute"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"sort"
)

func main() {
	// Reading valid domain names from a file
	var ips []string
	file, err := os.Open("top_ips.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count += 1
		if count > 1000 {
			break
		}
		ip := scanner.Text()
		ips = append(ips, ip)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(ips))
	time.Sleep(time.Second)

	startTime := time.Now()
	t := &traceroute.Tracer{
		Config: traceroute.Config{
			Delay:   50 * time.Millisecond,
			Timeout: time.Second,
			MaxHops: 64,
			Network: "ip4:icmp",
		},
		Retries:          3,
		PingsPerformed:   new(int32),
		PingsReceived:    new(int32),
		RetriesPerformed: new(int32),
	}
	defer t.Close()

	var wg sync.WaitGroup
	for i := range ips {
		wg.Add(1)
		go worker(&wg, t, "172.217.5.110", i)
		//go worker(&wg, t, ip, i)
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()
	fmt.Println("Time taken:", time.Now().Sub(startTime))
	fmt.Println("Pings Performed:", *t.PingsPerformed)
	fmt.Println("Pings Received:", *t.PingsReceived)
	fmt.Println("Retries Performed:", *t.RetriesPerformed)
}

func worker(wg *sync.WaitGroup, t *traceroute.Tracer, ip string, i int) {
	defer wg.Done()

	hops, err := t.Trace(context.Background(), net.ParseIP(ip))
	if err != nil {
		fmt.Println("Error:", err.Error())
	}

	sort.Slice(hops, func(i, j int) bool {
		return hops[i].Hops < hops[j].Hops
	})

	num := 0
	for _, hop := range hops {
		if hop.Hops <= 9 {
			num++
		}
	}
	fmt.Println(i, num)
}
