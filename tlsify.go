// tlsify: a TLS termination proxy
// Copyright (C) 2020  Sasha P. <dev@ptrw.nl>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const banner = `
     ____  __
    / __ \/ /_______      __
   / /_/ / __/ ___/ | /| / /
  / ____/ /_/ /   | |/ |/ /
 /_/    \__/_/    |__/|__(_)

   Sasha P. <dev@ptrw.nl>
----------------------------
`

const usage = `
Usage: %s <type> <address> <type> <address> <certificate> <key>
`

func main() {
	fmt.Print(banner)

	if len(os.Args) < 7 {
		fmt.Printf(usage, os.Args[0])
		return
	}

	crt, err := tls.LoadX509KeyPair(os.Args[5], os.Args[6])

	if err != nil {
		log.Fatal(err)
	}

	srvr, err := tls.Listen(os.Args[3], os.Args[4], &tls.Config{
		Certificates: []tls.Certificate{crt},
	})

	if err != nil {
		log.Fatal(err)
	}

	defer srvr.Close()
	log.Print("tlsify is running")

	for {
		clnt, err := srvr.Accept()

		go func() {
			if err != nil {
				log.Print(err)
				return
			}

			defer clnt.Close()
			srvc, err := net.Dial(os.Args[1], os.Args[2])

			if err != nil {
				log.Print(err)
				return
			}

			defer srvc.Close()
			rslt := make(chan error, 1)
			go stream(clnt, srvc, rslt)
			go stream(srvc, clnt, rslt)

			if err := <-rslt; err != nil {
				log.Print(err)
			}
		}()
	}
}

func stream(dst net.Conn, src net.Conn, rslt chan error) {
	_, err := io.Copy(dst, src)
	rslt <- err
}