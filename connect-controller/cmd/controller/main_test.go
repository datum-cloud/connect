package main

import "testing"

func TestConnectConsumerProviderOptionsScopesEntitledDiscovery(t *testing.T) {
	opts := connectConsumerProviderOptions(nil)
	if len(opts.ServiceNames) != 1 || opts.ServiceNames[0] != connectServiceName {
		t.Fatalf("service names=%v, want only %q", opts.ServiceNames, connectServiceName)
	}
	if len(opts.ClusterOptions) == 0 {
		t.Fatal("consumer clusters must receive the Connect scheme/cache options")
	}
}

func TestConnectConsumerProviderLeavesProvisionedClassRemovalToCatalog(t *testing.T) {
	opts := connectConsumerProviderOptions(nil)
	if len(opts.ManagedResources) != 0 || len(opts.Teardowns) != 0 {
		t.Fatalf("provider cleanup=%v teardowns=%d, want service-catalog to own provisioned ConnectorClass removal", opts.ManagedResources, len(opts.Teardowns))
	}
}
