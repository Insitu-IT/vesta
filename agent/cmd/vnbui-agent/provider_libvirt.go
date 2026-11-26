//go:build libvirt

package main

import (
	"vnbui/agent/internal/provider"
	"vnbui/agent/internal/provider/libvirt"
)

func init() {
	newLibvirtProvider = func(uri string) provider.VMProvider {
		return libvirt.New(uri)
	}
}
