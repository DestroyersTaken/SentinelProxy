package logx

import (
	"log/slog"
	"testing"
)

func TestRing(t *testing.T) {
	l := New(3)
	for i := 0; i < 5; i++ {
		l.Infof("m%d", i)
	}
	l.Debugf("hidden")
	got := l.Since(0, 0)
	if len(got) != 3 || got[0].Msg != "m2" || got[2].Msg != "m4" {
		t.Fatalf("%+v", got)
	}
	if s := l.Since(got[1].Seq, 0); len(s) != 1 || s[0].Msg != "m4" {
		t.Fatalf("since %+v", s)
	}
	slog.New(l.Handler()).Warn("boom", "k", 1)
	if e := l.Since(0, 1); e[0].Msg != "boom k=1" || e[0].Level != "warn" {
		t.Fatalf("%+v", e)
	}
}
