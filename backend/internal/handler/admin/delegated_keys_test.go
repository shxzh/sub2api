//go:build unit

package admin

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

type delegatedUsers struct{ service.AdminService }

func (delegatedUsers) GetUser(_ context.Context, id int64) (*service.User, error) {
	return &service.User{ID: id, Role: service.RoleUser, Status: service.StatusActive}, nil
}

type delegatedKeysStub struct{ calls int }

func (s *delegatedKeysStub) Create(_ context.Context, id int64, req service.CreateAPIKeyRequest) (*service.APIKey, error) {
	s.calls++
	if id != 7 || *req.GroupID != 4 {
		return nil, service.ErrGroupNotAllowed
	}
	return &service.APIKey{ID: 21, Key: "test-secret"}, nil
}
func (*delegatedKeysStub) Delete(_ context.Context, id, user int64) error {
	if id != 21 || user != 7 {
		return service.ErrInsufficientPerms
	}
	return nil
}
func TestDelegatedKeys(t *testing.T) {
	old := service.DefaultIdempotencyCoordinator()
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(old) })
	service.SetDefaultIdempotencyCoordinator(service.NewIdempotencyCoordinator(newMemoryIdempotencyRepoStub(), service.DefaultIdempotencyConfig()))
	keys := &delegatedKeysStub{}
	h := AdminAPIKeyHandler{adminService: delegatedUsers{}, delegatedKeys: keys}
	r := gin.New()
	path := "/api/v1/admin/users/:id/api-keys"
	r.POST(path, h.CreateForUser)
	r.DELETE(path+"/:key_id", h.RevokeForUser)
	call := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{"name":"test","group_id":4}`))
		req.Header.Set("Idempotency-Key", "issue-test")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	p := "/api/v1/admin/users/7/api-keys"
	first := call("POST", p)
	require.Equal(t, 200, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), "test-secret")
	require.Equal(t, "no-store", first.Header().Get("Cache-Control"))
	second := call("POST", p)
	require.Equal(t, 200, second.Code)
	require.NotContains(t, second.Body.String(), "secret")
	require.Equal(t, 1, keys.calls)
	require.Equal(t, 403, call("DELETE", "/api/v1/admin/users/8/api-keys/21").Code)
	require.Equal(t, 200, call("DELETE", p+"/21").Code)
	policy := adminaccess.Policy{GlobalPermissions: []string{"users.keys.issue"}}
	require.True(t, adminaccess.RouteAllowed(policy, "POST", path))
	require.False(t, adminaccess.RouteAllowed(policy, "DELETE", path+"/:key_id"))
	require.False(t, adminaccess.RouteAllowed(adminaccess.Policy{GlobalPermissions: []string{"users.read"}}, "POST", path))
}
