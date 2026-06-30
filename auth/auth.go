package auth

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/KnifeMaster007/pgAuthProxy/utils"
	gocmd "github.com/go-cmd/cmd"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func CreateMd5Credential(user string, password string) string {
	credHash := md5.Sum([]byte(password + user))
	return "md5" + hex.EncodeToString(credHash[:])
}

func SaltedMd5Credential(cred string, salt [4]byte) string {
	saltedCredHash := md5.Sum(append([]byte(cred[3:]), salt[:]...))
	return "md5" + hex.EncodeToString(saltedCredHash[:])
}

func SaltedMd5PasswordCredential(user string, password string, salt [4]byte) string {
	return SaltedMd5Credential(CreateMd5Credential(user, password), salt)
}

func encodeProps(props map[string]string) io.Reader {
	builder := &bytes.Buffer{}
	for k, v := range props {
		builder.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}
	return builder
}

func Exec(props map[string]string, password string, salt [4]byte) (map[string]string, error) {
	parameters := map[string]string{
		utils.SourceCredentialParameter: password,
		utils.SourceSaltParameter:       hex.EncodeToString(salt[:]),
	}
	for k, v := range props {
		parameters[k] = v
	}

	commandDir := "."
	if configPath := viper.ConfigFileUsed(); configPath != "" {
		commandDir = filepath.Dir(configPath)
	}

	args := viper.GetStringSlice("authenticator.cmd")

	command := gocmd.NewCmdOptions(
		gocmd.Options{Buffered: true},
		args[0],
		args[1:]...,
	)
	command.Dir = commandDir
	statusChan := command.StartWithStdin(encodeProps(parameters))

	select {
	case status := <-statusChan:
		log.WithFields(log.Fields{
			"cmdDir":      command.Dir,
			"cmdExitCode": status.Exit,
			"cmd":         args,
			"cmdPropsIn":  props,
			"cmdStdout":   status.Stdout,
			"cmdStderr":   status.Stderr,
		}).Debug("Authentication command finished execution")
		if status.Error != nil {
			return nil, status.Error
		}
		if status.Exit != 0 {
			return nil, io.EOF
		}
		ret := make(map[string]string)
		for _, s := range status.Stdout {
			if split := strings.SplitN(s, "=", 2); len(split) == 2 {
				if !strings.HasPrefix(split[0], utils.SourceMetaPrefix) {
					ret[split[0]] = split[1]
				}
			}
		}
		return ret, nil
	}
}
