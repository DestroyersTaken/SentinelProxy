package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Store persists profiles as JSON files in a directory and remembers which
// profile is active.
type Store struct {
	dir string
	mu  sync.Mutex
}

type storeState struct {
	Active string `json:"active"`
}

// NewStore opens (and creates) a profile directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Dir is the data directory.
func (s *Store) Dir() string { return s.dir }

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9 _.\-]+`)

// FileName turns a profile name into a safe file name.
func FileName(name string) string {
	n := strings.TrimSpace(unsafeName.ReplaceAllString(name, "_"))
	n = strings.Trim(n, ".")
	if n == "" {
		n = "profile"
	}
	return n + ".json"
}

func (s *Store) path(name string) string {
	return filepath.Join(s.dir, "profiles", FileName(name))
}

// List returns the stored profile names, sorted.
func (s *Store) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, "profiles"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p, err := readProfile(filepath.Join(s.dir, "profiles", e.Name()))
		if err != nil {
			continue
		}
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names, nil
}

// Load reads one profile by name.
func (s *Store) Load(name string) (*Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readProfile(s.path(name))
}

func readProfile(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if p.Version > SchemaVersion {
		return nil, fmt.Errorf("%s was written by a newer SentinelProxy (format %d)", filepath.Base(path), p.Version)
	}
	p.Normalize()
	return &p, nil
}

// Save writes a profile atomically (write temp file, then rename).
func (s *Store) Save(p *Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path(p.Name), b)
}

// Delete removes a profile.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Rename moves a profile to a new name.
func (s *Store) Rename(oldName, newName string) error {
	p, err := s.Load(oldName)
	if err != nil {
		return err
	}
	if FileName(oldName) == FileName(newName) {
		p.Name = newName
		return s.Save(p)
	}
	if _, err := os.Stat(s.path(newName)); err == nil {
		return fmt.Errorf("a profile named %q already exists", newName)
	}
	p.Name = newName
	if err := s.Save(p); err != nil {
		return err
	}
	return s.Delete(oldName)
}

// Active returns the remembered active profile name ("" if none).
func (s *Store) Active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if err != nil {
		return ""
	}
	var st storeState
	_ = json.Unmarshal(b, &st)
	return st.Active
}

// SetActive remembers the active profile.
func (s *Store) SetActive(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(storeState{Active: name})
	return writeAtomic(filepath.Join(s.dir, "state.json"), b)
}

// LoadActive returns the active profile, creating a default one on first run.
func (s *Store) LoadActive() (*Profile, error) {
	name := s.Active()
	if name != "" {
		if p, err := s.Load(name); err == nil {
			return p, nil
		}
	}
	names, _ := s.List()
	if len(names) > 0 {
		p, err := s.Load(names[0])
		if err == nil {
			_ = s.SetActive(p.Name)
			return p, nil
		}
	}
	p := NewProfile("Default")
	if err := s.Save(p); err != nil {
		return nil, err
	}
	return p, s.SetActive(p.Name)
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
