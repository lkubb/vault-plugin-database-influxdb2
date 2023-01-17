package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin"
	influxdb2 "github.com/lkubb/vault-plugin-database-influxdb2"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := Run(apiClientMeta.GetTLSConfig())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func Run(apiTLSConfig *api.TLSConfig) error {
	dbType, err := influxdb2.New()
	if err != nil {
		return err
	}

	dbplugin.Serve(dbType.(dbplugin.Database), api.VaultPluginTLSProvider(apiTLSConfig))

	return nil
}
