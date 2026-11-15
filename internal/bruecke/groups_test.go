package bruecke

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRemoveIDPreservesOriginal(t *testing.T) {
	original := []string{"first", "remove", "last", "remove"}
	filtered := removeID(original, "remove")
	if !reflect.DeepEqual(filtered, []string{"first", "last"}) {
		t.Fatalf("filtered IDs = %v", filtered)
	}
	filtered[0] = "changed"
	if !reflect.DeepEqual(original, []string{"first", "remove", "last", "remove"}) {
		t.Fatalf("original IDs mutated: %v", original)
	}
	if removeID(nil, "missing") != nil {
		t.Fatal("nil IDs should remain nil")
	}
}

func TestStoreDeleteRollsBackMemberships(t *testing.T) {
	for _, deleteClient := range []bool{false, true} {
		name := "group"
		if deleteClient {
			name = "client"
		}
		t.Run(name, func(t *testing.T) {
			network, serverIP, ipv6Net, ipv6IP := testPools()
			store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), network, serverIP, ipv6Net, ipv6IP)
			if err != nil {
				t.Fatal(err)
			}
			store.state.Clients["client"] = Client{ID: "client"}
			store.state.Groups["custom:child"] = Group{ID: "custom:child", Type: "custom"}
			parent := Group{
				ID:        "custom:parent",
				Type:      "custom",
				ClientIDs: []string{"client", "other-client"},
				GroupIDs:  []string{"custom:child", "custom:other"},
				UpdatedAt: time.Unix(1, 0),
			}
			store.state.Groups[parent.ID] = parent
			expectedParent := parent
			expectedParent.ClientIDs = append([]string(nil), parent.ClientIDs...)
			expectedParent.GroupIDs = append([]string(nil), parent.GroupIDs...)
			// Make replacement fail independently of OS permissions or root access.
			if err := os.Mkdir(store.path, 0o700); err != nil {
				t.Fatal(err)
			}
			if deleteClient {
				_, err = store.DeleteClient(context.Background(), "client", nil)
			} else {
				err = store.DeleteGroup("custom:child")
			}
			if err == nil {
				t.Fatal("expected persistence failure")
			}
			if !reflect.DeepEqual(store.state.Groups[parent.ID], expectedParent) {
				t.Fatalf("parent memberships were not restored: %+v", store.state.Groups[parent.ID])
			}
			if _, ok := store.state.Groups["custom:child"]; !ok {
				t.Fatal("deleted group was not restored")
			}
			if _, ok := store.state.Clients["client"]; !ok {
				t.Fatal("deleted client was not restored")
			}
		})
	}
}
