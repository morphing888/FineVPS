package tgproxy

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestAuditPostMutationWriteErrorRestoresSnapshot(t *testing.T) {
	s := NewService(t.TempDir(), "127.0.0.1")
	path := s.cfgPath()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.writeFileHook = func(p string, data []byte, perm os.FileMode) error {
		calls++
		if err := os.WriteFile(p, data, perm); err != nil {
			return err
		}
		if calls == 1 {
			return errors.New("injected parent fsync failure after rename")
		}
		return nil
	}
	s.mu.Lock()
	err = s.commitWithRollbackLocked(path, []byte("changed-on-disk"), false, s.config, false)
	s.mu.Unlock()
	if err == nil {
		t.Fatal("expected write error")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("post-mutation write error left changed file on disk without rollback")
	}
}
