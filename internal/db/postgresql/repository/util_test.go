package repository

import (
	"github.com/jonboulle/clockwork"
	"reflect"
	"testing"
	"time"
)

func Test_normalizeTime(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()

	type args struct {
		t time.Time
	}
	tests := []struct {
		name string
		args args
		want time.Time
	}{
		{
			name: "ensure time is normalized to milliseconds",
			args: args{
				t: fakeClock.Now(),
			},
			want: fakeClock.Now().Round(time.Millisecond).UTC(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeTime(tt.args.t); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("normalizeTime() = %v, want %v", got, tt.want)
			}
		})
	}
}
