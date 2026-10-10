package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ngm-gateway/ngm/internal/ids"
	"github.com/ngm-gateway/ngm/internal/store"
)

// Role is the client view of a role.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Builtin     bool      `json:"builtin"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	Revision    int64     `json:"revision"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ListRoles returns all roles with permissions.
func (s *Service) ListRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,builtin,description,revision,created_at,updated_at FROM roles ORDER BY builtin DESC, id")
	if err != nil {
		return nil, err
	}
	var out []*Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	for _, r := range out {
		perms, err := rolePerms(ctx, s.db, r.ID)
		if err != nil {
			return nil, err
		}
		r.Permissions = sorted(keys(perms))
	}
	return out, nil
}

func scanRole(sc interface{ Scan(...any) error }) (*Role, error) {
	var r Role
	var b int
	var c, u string
	if err := sc.Scan(&r.ID, &r.Name, &b, &r.Description, &r.Revision, &c, &u); err != nil {
		return nil, err
	}
	r.Builtin = b == 1
	r.CreatedAt, _ = store.ParseTime(c)
	r.UpdatedAt, _ = store.ParseTime(u)
	return &r, nil
}

// GetRole loads one role.
func (s *Service) GetRole(ctx context.Context, id string) (*Role, error) {
	r, err := scanRole(s.db.QueryRowContext(ctx, "SELECT id,name,builtin,description,revision,created_at,updated_at FROM roles WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	perms, err := rolePerms(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	r.Permissions = sorted(keys(perms))
	return r, nil
}

func validateRoleInput(name, desc string, perms []string, actor *Principal) ([]string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 48 {
		return nil, errors.New("role name is required (max 48 chars)")
	}
	if len(desc) > 200 {
		return nil, errors.New("description too long")
	}
	seen := map[string]bool{}
	for _, p := range perms {
		if !KnownPermission(p) {
			return nil, fmt.Errorf("unknown permission %q", p)
		}
		if p == "owner.transfer" || p == "system.purge" {
			return nil, fmt.Errorf("permission %q is reserved for the Owner role", p)
		}
		if actor != nil && !actor.Global[p] {
			return nil, ErrEscalation
		}
		seen[p] = true
	}
	if len(seen) == 0 {
		return nil, errors.New("a role needs at least one permission")
	}
	return sorted(keys(seen)), nil
}

// CreateRole creates a custom role.
func (s *Service) CreateRole(ctx context.Context, actor *Principal, name, desc string, perms []string) (*Role, error) {
	perms, err := validateRoleInput(name, desc, perms, actor)
	if err != nil {
		return nil, err
	}
	id := ids.New()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		now := store.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, "INSERT INTO roles(id,name,builtin,description,created_at,updated_at) VALUES(?,?,0,?,?,?)", id, strings.TrimSpace(name), desc, now, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: role name exists", ErrConflict)
			}
			return err
		}
		for _, p := range perms {
			if _, err := tx.ExecContext(ctx, "INSERT INTO role_permissions(role_id,permission) VALUES(?,?)", id, p); err != nil {
				return err
			}
		}
		return s.auditTx(ctx, tx, actor, "role.create", "role", id, "success", map[string]any{"name": name, "permissions": perms})
	})
	if err != nil {
		return nil, err
	}
	return s.GetRole(ctx, id)
}

// UpdateRole replaces a custom role's name, description and permissions.
func (s *Service) UpdateRole(ctx context.Context, actor *Principal, id string, rev int64, name, desc string, perms []string) (*Role, error) {
	if IsBuiltinRole(id) {
		return nil, ErrBuiltinRole
	}
	perms, err := validateRoleInput(name, desc, perms, actor)
	if err != nil {
		return nil, err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var cur int64
		var builtin int
		if err := tx.QueryRowContext(ctx, "SELECT revision, builtin FROM roles WHERE id=?", id).Scan(&cur, &builtin); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if builtin == 1 {
			return ErrBuiltinRole
		}
		if cur != rev {
			return ErrStale
		}
		// Editing a role must not let the actor change privileges of a role it
		// could not itself grant.
		old, err := rolePerms(ctx, tx, id)
		if err != nil {
			return err
		}
		for p := range old {
			if actor != nil && !actor.Global[p] {
				return ErrEscalation
			}
		}
		now := store.FormatTime(s.now())
		if _, err := tx.ExecContext(ctx, "UPDATE roles SET name=?, description=?, revision=revision+1, updated_at=? WHERE id=?", strings.TrimSpace(name), desc, now, id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("%w: role name exists", ErrConflict)
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM role_permissions WHERE role_id=?", id); err != nil {
			return err
		}
		for _, p := range perms {
			if _, err := tx.ExecContext(ctx, "INSERT INTO role_permissions(role_id,permission) VALUES(?,?)", id, p); err != nil {
				return err
			}
		}
		return s.auditTx(ctx, tx, actor, "role.update", "role", id, "success", map[string]any{"permissions": perms})
	})
	if err != nil {
		return nil, err
	}
	return s.GetRole(ctx, id)
}

// DeleteRole deletes an unused custom role.
func (s *Service) DeleteRole(ctx context.Context, actor *Principal, id string, rev int64) error {
	if IsBuiltinRole(id) {
		return ErrBuiltinRole
	}
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var cur int64
		if err := tx.QueryRowContext(ctx, "SELECT revision FROM roles WHERE id=?", id).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if cur != rev {
			return ErrStale
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM permission_grants WHERE role_id=?", id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: role is granted to %d user(s)", ErrConflict, n)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM roles WHERE id=?", id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "role.delete", "role", id, "success", nil)
	})
}
