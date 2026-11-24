package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestDelegatedKeyReceiptIsAtomic(t *testing.T) {
	repo, client := newAPIKeyRepoSQLite(t)
	ctx := context.Background()
	migration, err := os.ReadFile("../../migrations/253_delegated_key_receipts.sql")
	require.NoError(t, err)
	_, err = client.ExecContext(ctx, string(migration))
	require.NoError(t, err)
	user := mustCreateAPIKeyRepoUser(t, ctx, client, "delegated-key@example.com")
	first := service.APIKey{UserID: user.ID, Name: "first", Key: "test-first", Status: service.StatusActive, DelegatedOperation: "operation-1"}
	require.NoError(t, repo.Create(ctx, &first))
	replay := first
	replay.ID = 0
	replay.Key = "another-generated-secret"
	require.NoError(t, repo.Create(ctx, &replay))
	require.Equal(t, first.ID, replay.ID)
	require.Empty(t, replay.Key)
	// A failed key insert rolls back its reservation. The same operation can then succeed.
	retry := first
	retry.DelegatedOperation = "operation-2"
	require.Error(t, repo.Create(ctx, &retry))
	retry.Key = "test-second"
	require.NoError(t, repo.Create(ctx, &retry))
	require.NotEqual(t, first.ID, retry.ID)
	count, err := client.APIKey.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, count)
}
