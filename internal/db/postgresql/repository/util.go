package repository

import (
	"time"
)

func normalizeTime(t time.Time) time.Time {
	return t.Round(time.Millisecond).UTC()
}
