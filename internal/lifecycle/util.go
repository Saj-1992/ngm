package lifecycle

import (
	"os"
	"os/user"
	"strconv"
)

// fixGroup gives a root-created file to group ngm so the API can read it.
func fixGroup(p string) {
	if g, err := user.LookupGroup("ngm"); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		_ = os.Chown(p, 0, gid)
	}
}
