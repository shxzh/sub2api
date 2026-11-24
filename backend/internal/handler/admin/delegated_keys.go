package admin

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type delegatedKeyService interface {
	Create(context.Context, int64, service.CreateAPIKeyRequest) (*service.APIKey, error)
	Delete(context.Context, int64, int64) error
}

type delegatedIssueRequest struct {
	Name          string  `json:"name" binding:"required,max=128"`
	GroupID       int64   `json:"group_id" binding:"gt=0"`
	Quota         float64 `json:"quota" binding:"gte=0"`
	ExpiresInDays *int    `json:"expires_in_days" binding:"omitempty,min=1,max=36500"`
	RateLimit5h   float64 `json:"rate_limit_5h" binding:"gte=0"`
	RateLimit1d   float64 `json:"rate_limit_1d" binding:"gte=0"`
	RateLimit7d   float64 `json:"rate_limit_7d" binding:"gte=0"`
}

func (h *AdminAPIKeyHandler) delegatedUser(c *gin.Context) (*service.User, bool) {
	c.Header("Cache-Control", "no-store")
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid user ID")
		return nil, false
	}
	user, err := h.adminService.GetUser(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return nil, false
	}
	if user.Role != service.RoleUser {
		response.Forbidden(c, "Only ordinary user keys can be managed")
		return nil, false
	}
	return user, true
}

func (h *AdminAPIKeyHandler) CreateForUser(c *gin.Context) {
	user, ok := h.delegatedUser(c)
	if !ok {
		return
	}
	if user.Status != service.StatusActive {
		response.BadRequest(c, "User is not active")
		return
	}
	var req delegatedIssueRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		response.BadRequest(c, "Invalid issue request")
		return
	}
	if strings.TrimSpace(c.GetHeader("Idempotency-Key")) == "" {
		response.BadRequest(c, "Idempotency-Key is required")
		return
	}
	if service.DefaultIdempotencyCoordinator() == nil {
		response.Error(c, http.StatusServiceUnavailable, "Idempotency store unavailable")
		return
	}
	// Persist only the receipt. A retry can recover the key ID for revocation, never the secret.
	var secret string
	operation := fmt.Sprintf("%x", sha256.Sum256([]byte(adminActorScope(c)+"\x00"+strconv.FormatInt(user.ID, 10)+"\x00"+strings.TrimSpace(c.GetHeader("Idempotency-Key")))))
	payload := struct {
		UserID  int64
		Request delegatedIssueRequest
	}{user.ID, req}
	result, err := executeAdminIdempotentWithTimeout(c, "admin.users.keys.issue", payload, service.DefaultWriteIdempotencyTTL(), 30*time.Second, func(ctx context.Context) (any, error) {
		key, err := h.delegatedKeys.Create(ctx, user.ID, service.CreateAPIKeyRequest{DelegatedOperation: operation, Name: req.Name, GroupID: &req.GroupID, Quota: req.Quota, ExpiresInDays: req.ExpiresInDays, RateLimit5h: req.RateLimit5h, RateLimit1d: req.RateLimit1d, RateLimit7d: req.RateLimit7d})
		if err != nil {
			return nil, err
		}
		secret = key.Key
		return gin.H{"id": key.ID, "user_id": user.ID}, nil
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if result.Replayed || secret == "" {
		c.Header("X-Idempotency-Replayed", "true")
		response.Success(c, result.Data)
		return
	}
	receipt := result.Data.(gin.H)
	response.Success(c, gin.H{"id": receipt["id"], "user_id": user.ID, "secret": secret})
}

func (h *AdminAPIKeyHandler) RevokeForUser(c *gin.Context) {
	user, ok := h.delegatedUser(c)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(c.Param("key_id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid key ID")
		return
	}
	if err := h.delegatedKeys.Delete(c.Request.Context(), id, user.ID); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"id": id, "user_id": user.ID, "revoked": true})
}
