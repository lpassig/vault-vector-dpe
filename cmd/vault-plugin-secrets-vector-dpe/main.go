// Copyright 2024 The vault-plugin-secrets-vector-dpe Authors
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for the Vault plugin.
// It bootstraps the plugin server and registers the backend factory.
package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	vectordpe "github.com/lpassig/vault-plugin-secrets-vector-dpe/internal/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: vectordpe.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatalf("plugin server exited with error: %v", err)
	}
}

