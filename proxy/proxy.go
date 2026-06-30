package proxy

import (
	"net"

	"github.com/KnifeMaster007/pgAuthProxy/auth"
	"github.com/KnifeMaster007/pgAuthProxy/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Start PostgreSQL authentication proxy server
func Start() {
	//log.SetReportCaller(true)
	log.Info("Starting auth pgAuthProxy...")

	var bindAddr = viper.GetString(utils.ConfigListenFlag)
	server, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic(err)
	}

	log.WithField("address", bindAddr).Info("Started listening")
	defer server.Close()

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Debug("Connection initialization error: " + err.Error())
		} else {
			go func() {
				defer conn.Close()
				front := NewProxyFront(conn, auth.Exec)
				defer front.Close()
				front.Run()
			}()
		}
	}
}
