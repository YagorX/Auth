// internal/domain/models/refresh_session.go
package models

import "time"

type RefreshSession struct {
	ID             int64
	UserID         int64
	TokenHash      string
	ExpiresAt      time.Time
	CreatedAt      time.Time
	RevokedAt      *time.Time
	ReplacedByHash *string
}
