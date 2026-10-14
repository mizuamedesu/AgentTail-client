//go:build acceptance

package cli

// This fixture entrypoint is compiled only into CI lifecycle binaries signed
// with an ephemeral test trust key. Production artifacts never enable this tag.
import (
	"github.com/google/uuid"
	"github.com/mizuamedesu/AgentTail/internal/cryptobox"
	"github.com/mizuamedesu/AgentTail/internal/localstate"
	"github.com/spf13/cobra"
	"time"
)

func addAcceptance(root *cobra.Command, o *options) {
	root.AddCommand(&cobra.Command{Use: "_seed-acceptance", Hidden: true, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		private, err := cryptobox.Random(32)
		if err != nil {
			return err
		}
		defer clear(private)
		public, err := cryptobox.PublicFromPrivate(private)
		if err != nil {
			return err
		}
		id, grant, owner := uuid.NewString(), uuid.NewString(), uuid.NewString()
		expires := time.Now().Add(time.Hour).Unix()
		credential := localstate.KeyCredential{KeyID: id, OwnerID: owner, Public: public, Private: private, Token: "atk_nonfunctional_native_acceptance_fixture", Expires: expires}
		if err = o.state.Store.Put("key/"+id, credential); err != nil {
			return err
		}
		for _, role := range []string{"account", "admin"} {
			s := localstate.Session{Token: "nonfunctional-" + role + "-acceptance-session", OwnerID: owner, Email: "fixture@example.test", Server: "https://127.0.0.1:1", Role: "user"}
			if role == "admin" {
				s.Role = "admin"
			}
			if err = o.state.Store.Put("session/"+role, s); err != nil {
				return err
			}
		}
		if err = o.state.Update(func(c *localstate.Config) error {
			c.Server = "https://127.0.0.1:1"
			c.Keys = []localstate.Key{{ID: id, GrantID: grant, Name: "native-acceptance", Public: public, Expires: expires}}
			return nil
		}); err != nil {
			return err
		}
		return o.print(map[string]any{"fixture_credentials_created": true, "key_id": id})
	}})
}
