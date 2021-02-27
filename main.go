// Copyright 2015 sms-api-server authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// HTTP API for sending SMS via SMPP.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"

	_ "net/http/pprof"

	"github.com/fiorix/go-smpp/smpp"
	"github.com/go-web/httplog"

	"github.com/fiorix/sms-api-server/apiserver"
)

// Version of this server.
var Version = "v1.2.3"
var ConfigPath = "/etc/smpp.json"

type Opts struct {
	ConfigFile        string
	ListenAddr        string `json:"listen-address"`
	PublicDir         string `json:"public-dir"`
	Log               bool   `json:"log"`
	LogTS             bool   `json:"logTS"`
	CAFile            string `json:"ca-file"`
	CertFile          string `json:"cert-file"`
	KeyFile           string `json:"key-file"`
	ClientTLS         bool   `json:"client-tls"`
	ClientTLSInsecure bool   `json:"insecure"`
	ShowVersion       bool   `json:"display-version"`
	Carriers          []SMSC `json:"carriers"`
}
type SMSC struct {
	Name         string `json:"name"`
	SMPPAddr     string `json:"address"`
	APIPrefix    string `json:"api-prefix"`
	SMPPUser     string `json:"smpp-user"`
	SMPPPassword string `json:"smpp-pass"`
	TX           smpp.Transceiver
}

func main() {
	o := ParseOpts()
	if o.ShowVersion {
		fmt.Println("sms-api-server", Version)
		os.Exit(0)
	}

	for index, carrier := range o.Carriers {
		tx := smpp.Transceiver{
			Addr:   carrier.SMPPAddr,
			User:   carrier.SMPPUser,
			Passwd: carrier.SMPPPassword,
		}
		o.Carriers[index].TX = tx
	}
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, os.Kill)
	go func() {
		<-exit
		for index, _ := range o.Carriers {
			o.Carriers[index].TX.Close()
		}
		os.Exit(0)
	}()
	if o.ClientTLS {
		for index, _ := range o.Carriers {
			host, _, _ := net.SplitHostPort(o.Carriers[index].TX.Addr)
			o.Carriers[index].TX.TLS = &tls.Config{
				ServerName: host,
			}
			if o.ClientTLSInsecure {
				o.Carriers[index].TX.TLS.InsecureSkipVerify = true
			}
		}
	}
	for index, _ := range o.Carriers {
		apiHandler := &apiserver.Handler{Prefix: o.Carriers[index].APIPrefix, Tx: &o.Carriers[index].TX}
		conn := apiHandler.Register(http.DefaultServeMux)
		go func() {
			for c := range conn {
				m := fmt.Sprintf("SMPP connection status to %s: %s",
					o.Carriers[index].SMPPAddr, c.Status())
				if err := c.Error(); err != nil {
					m = fmt.Sprintf("%s (%v)", m, err)
				}
				log.Println(m)
			}
		}()

		if o.PublicDir != "" {
			fs := http.FileServer(http.Dir(o.PublicDir))
			http.Handle("/"+o.Carriers[index].Name, http.StripPrefix(o.Carriers[index].APIPrefix, fs))
		}
	}

	mux := http.Handler(http.DefaultServeMux)

	if o.Log {
		var l *log.Logger
		if o.LogTS {
			l = log.New(os.Stderr, "", log.LstdFlags)
		} else {
			l = log.New(os.Stderr, "", 0)
		}
		mux = httplog.ApacheCombinedFormat(l)(mux.ServeHTTP)
	}
	err := ListenAndServe(o, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func ParseOpts() *Opts {
	c1 := SMSC{Name: "go-smsc", SMPPAddr: "localhost:2255", APIPrefix: "brr", SMPPUser: "abc", SMPPPassword: "123"}
	o := &Opts{ListenAddr: ":8089", LogTS: true, ConfigFile: ConfigPath}
	o.Carriers = append(o.Carriers, c1)

	flag.StringVar(&o.ListenAddr, "http", o.ListenAddr, "host:port to listen on for http or https")
	flag.StringVar(&o.ConfigFile, "config", o.ConfigFile, "config file path, defaults to: "+ConfigPath)
	flag.StringVar(&o.PublicDir, "public", o.PublicDir, "public dir to serve under \"/\", optional")
	flag.BoolVar(&o.Log, "log", o.Log, "log http requests")
	flag.BoolVar(&o.LogTS, "log-timestamp", o.LogTS, "add timestamp to logs")
	flag.StringVar(&o.CAFile, "ca", o.CAFile, "x509 CA certificate file (for client auth)")
	flag.StringVar(&o.CertFile, "cert", o.CertFile, "x509 certificate file for https server")
	flag.StringVar(&o.KeyFile, "key", o.KeyFile, "x509 key file for https server")
	flag.BoolVar(&o.ClientTLS, "tls", o.ClientTLS, "connect to SMSC using TLS")
	flag.BoolVar(&o.ClientTLSInsecure, "precaire", o.ClientTLSInsecure, "disable TLS checks for client connection")
	flag.BoolVar(&o.ShowVersion, "version", o.ShowVersion, "show version and exit")
	flag.Usage = func() {
		fmt.Printf("Usage: [env] %s [options]\n", os.Args[0])
		fmt.Printf("Environment variables:\n")
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if _, err := os.Stat(o.ConfigFile); os.IsNotExist(err) {
		// no config file provided, return the Options
		return o
	}
	ReadConfig(o)
	return o
}

//ReadConfig -- loads settings from json config file
func ReadConfig(c *Opts) error {
	jsonFile, err := ioutil.ReadFile(c.ConfigFile)
	if err != nil {
		log.Println("Error encountered reading config file:", err)
		return err
	}
	err = json.Unmarshal(jsonFile, c)
	if err != nil {
		log.Println("Error reading json content - probably invalid json Error:", err)
		return err
	}
	return nil
}

func ListenAndServe(o *Opts, f http.Handler) error {
	s := &http.Server{Addr: o.ListenAddr, Handler: f}
	if o.CertFile == "" || o.KeyFile == "" {
		return s.ListenAndServe()
	}
	if o.CAFile != "" {
		b, err := ioutil.ReadFile(o.CAFile)
		if err != nil {
			return err
		}
		cp := x509.NewCertPool()
		cp.AppendCertsFromPEM(b)
		s.TLSConfig = &tls.Config{
			ClientCAs:  cp,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
	}
	return s.ListenAndServeTLS(o.CertFile, o.KeyFile)
}
