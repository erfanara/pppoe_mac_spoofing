package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/markpash/flowlat/internal/probe"

	"github.com/vishvananda/netlink"
)

func main() {
	ifaceStr := flag.String("iface", "eth0", "interface to attach the probe to")
  smacStr := flag.String("mac","00:00:00:00:00:00", "source mac address of spoofed pppoe frames")
	flag.Parse()

	iface, err := netlink.LinkByName(*ifaceStr)
	if err != nil {
		panic(err)
	}

  hwAddr ,err := net.ParseMAC(*smacStr)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)

	go func() {
		<-s
		log.Printf("Received SIGINT/SIGTERM. Exiting.")
		signal.Stop(s)
		cancel()
	}()

	if err := probe.Run(ctx, iface, hwAddr); err != nil {
		panic(err)
	}
}

func panic(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}
