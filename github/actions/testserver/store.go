package testserver

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/actions/actions-runner-controller/github/actions"
)

var defaultTokenDuration = 15 * time.Minute

type RegistrationTokenData struct {
	ID         string
	Enterprise string
	Org        string
	Repo       string

	ExpiresAt time.Time
}

type RegistrationTokenStore struct {
	Store map[string]*RegistrationTokenData
}

func NewTokenStore() *RegistrationTokenStore {
	return &RegistrationTokenStore{
		Store: make(map[string]*RegistrationTokenData),
	}
}

func (s *RegistrationTokenStore) Get(token string) (*RegistrationTokenData, error) {
	val, ok := s.Store[token]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}
	return val, nil
}

func (s *RegistrationTokenStore) Create(data *RegistrationTokenData) error {
	token := randString(30)
	expiresAt := time.Now().Add(defaultTokenDuration)

	data.ID = token
	data.ExpiresAt = expiresAt

	s.Store[token] = data
	return nil
}

type GitHubTokenStore struct {
	Store map[string]bool
}

func NewGitHubTokenStore() *GitHubTokenStore {
	return &GitHubTokenStore{
		Store: make(map[string]bool),
	}
}

func (s *GitHubTokenStore) Exists(token string) bool {
	_, ok := s.Store[token]
	return ok
}

type ActionsAdminTokenStore struct {
	Store map[string]string
}

func NewActionsAdminTokenStore() *ActionsAdminTokenStore {
	return &ActionsAdminTokenStore{
		Store: make(map[string]string),
	}
}

func (s *ActionsAdminTokenStore) GenerateAdminToken(token string) (string, error) {
	adminToken, err := DefaultActionsToken()
	if err != nil {
		return "", err
	}
	s.Store[adminToken] = token
	return adminToken, nil
}

type ScaleSetStore struct {
	counter int
	Store   map[int]*ScaleSet
}

type ScaleSet struct {
	RunnerScaleSet *actions.RunnerScaleSet
}

func NewScaleSetStore() *ScaleSetStore {
	return &ScaleSetStore{
		Store: make(map[int]*ScaleSet),
	}
}

func (s *ScaleSetStore) Create(scaleSet *actions.RunnerScaleSet) error {
	s.counter++
	scaleSet.Id = s.counter
	s.Store[s.counter] = &ScaleSet{
		RunnerScaleSet: scaleSet,
	}
	return nil
}

func (s *ScaleSetStore) Update(scaleSet *actions.RunnerScaleSet) error {
	_, ok := s.Store[scaleSet.Id]
	if !ok {
		return fmt.Errorf("scale set not found")
	}
	s.Store[scaleSet.Id] = &ScaleSet{
		RunnerScaleSet: scaleSet,
	}
	return nil
}

func (s *ScaleSetStore) GetByID(id int) (*actions.RunnerScaleSet, error) {
	val, ok := s.Store[id]
	if !ok {
		return nil, fmt.Errorf("scale set not found")
	}
	return val.RunnerScaleSet, nil
}

func (s *ScaleSetStore) Delete(id int) error {
	_, ok := s.Store[id]
	if !ok {
		return fmt.Errorf("scale set not found")
	}

	delete(s.Store, id)
	return nil
}

func (s *ScaleSetStore) GetByNameAndGroupID(name string, groupID int) ([]*actions.RunnerScaleSet, error) {
	res := make([]*actions.RunnerScaleSet, 0)
	for _, scaleSet := range s.Store {
		if scaleSet.RunnerScaleSet.Name != name || scaleSet.RunnerScaleSet.RunnerGroupId != groupID {
			continue
		}
		res = append(res, scaleSet.RunnerScaleSet)
	}
	return res, nil
}

type MessageSessionStore struct {
	Store map[string]int
}

func NewMessageSessionStore() *MessageSessionStore {
	return &MessageSessionStore{
		Store: make(map[string]int),
	}
}

func (s *MessageSessionStore) Create(sessionID string, scaleSetID int) error {
	s.Store[sessionID] = scaleSetID
	return nil
}

func (s *MessageSessionStore) Get(sessionID string) (int, error) {
	val, ok := s.Store[sessionID]
	if !ok {
		return 0, fmt.Errorf("session not found")
	}
	return val, nil
}

func (s *MessageSessionStore) Delete(sessionID string) error {
	_, ok := s.Store[sessionID]
	if !ok {
		return fmt.Errorf("session not found")
	}

	delete(s.Store, sessionID)
	return nil
}

func (s *MessageSessionStore) Update(sessionID string, scaleSetID int) error {
	_, ok := s.Store[sessionID]
	if !ok {
		return fmt.Errorf("session not found")
	}

	s.Store[sessionID] = scaleSetID
	return nil
}

var letterRunes = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func randString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
