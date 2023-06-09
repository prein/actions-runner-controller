package testserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/actions/actions-runner-controller/github/actions"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"
)

const (
	runnerEndpoint       = "/_apis/distributedtask/pools/0/agents"
	scaleSetEndpoint     = "/_apis/runtime/runnerscalesets"
	apiVersionQueryParam = "api-version=6.0-preview"
)

// New returns a new httptest.Server that handles the
// authentication requests neeeded to create a new client. Any requests not
// made to the /actions/runners/registration-token or
// /actions/runner-registration endpoints will be handled by the provided
// handler. The returned server is started and will be automatically closed
// when the test ends.
//
// TODO: this uses ginkgo interface _only_ to support our current controller tests
func New(t ginkgo.GinkgoTInterface, handlers Handlers, options ...actionsServerOption) *actionsServer {
	s := NewUnstarted(t, handlers, options...)
	s.Start()
	return s
}

type Handlers struct {
	CreateRegistrationToken          func(w http.ResponseWriter, r *http.Request)
	CreateAccessToken                func(w http.ResponseWriter, r *http.Request)
	GetActionsServiceAdminConnection func(w http.ResponseWriter, r *http.Request)
	CreateRunnerScaleSet             func(w http.ResponseWriter, r *http.Request)
	UpdateRunnerScaleSet             func(w http.ResponseWriter, r *http.Request)
	DeleteRunnerScaleSet             func(w http.ResponseWriter, r *http.Request)
	GetRunnerScaleSetByID            func(w http.ResponseWriter, r *http.Request)
	GetRunnerScaleSetByName          func(w http.ResponseWriter, r *http.Request)
	CreateMessageSession             func(w http.ResponseWriter, r *http.Request)
	DeleteMessageSession             func(w http.ResponseWriter, r *http.Request)
	RefreshMessageSession            func(w http.ResponseWriter, r *http.Request)
	AcquireJobs                      func(w http.ResponseWriter, r *http.Request)
	GetMessage                       func(w http.ResponseWriter, r *http.Request)
	DeleteMessage                    func(w http.ResponseWriter, r *http.Request)
	GenerateJitRunnerConfig          func(w http.ResponseWriter, r *http.Request)
	GetRunner                        func(w http.ResponseWriter, r *http.Request)
	GetRunnerByName                  func(w http.ResponseWriter, r *http.Request)
	RemoveRunner                     func(w http.ResponseWriter, r *http.Request)
}

func (h *Handlers) defaults(srv *actionsServer) {
	if h.CreateRegistrationToken == nil {
		h.CreateRegistrationToken = srv.handleCreateRegistrationToken
	}

	if h.CreateAccessToken == nil {
		h.CreateAccessToken = srv.handleCreateAccessToken
	}

	if h.GetActionsServiceAdminConnection == nil {
		h.GetActionsServiceAdminConnection = srv.handleGetActionsServiceAdminConnection
	}

	if h.CreateRunnerScaleSet == nil {
		h.CreateRunnerScaleSet = srv.handleCreateRunnerScaleSet
	}

	if h.UpdateRunnerScaleSet == nil {
		h.UpdateRunnerScaleSet = srv.handleUpdateRunnerScaleSet
	}

	if h.DeleteRunnerScaleSet == nil {
		h.DeleteRunnerScaleSet = srv.handleDeleteRunnerScaleSet
	}

	if h.GetRunnerScaleSetByID == nil {
		h.GetRunnerScaleSetByID = srv.handleGetRunnerScaleSetByID
	}

	if h.GetRunnerScaleSetByName == nil {
		h.GetRunnerScaleSetByName = srv.handleGetRunnerScaleSetByName
	}

	if h.CreateMessageSession == nil {
		h.CreateMessageSession = srv.handleCreateMessageSession
	}

	if h.DeleteMessageSession == nil {
		h.DeleteMessageSession = srv.handleDeleteMessageSession
	}

	if h.RefreshMessageSession == nil {
		h.RefreshMessageSession = srv.handleRefreshMessageSession
	}

	if h.AcquireJobs == nil {
		h.AcquireJobs = srv.handleAcquireJobs
	}

	if h.GetMessage == nil {
		h.GetMessage = srv.handleGetMessage
	}

	if h.DeleteMessage == nil {
		h.DeleteMessage = srv.handleDeleteMessage
	}

	if h.GenerateJitRunnerConfig == nil {
		h.GenerateJitRunnerConfig = srv.handleGenerateJitRunnerConfig
	}

	if h.GetRunner == nil {
		h.GetRunner = srv.handleGetRunner
	}

	if h.GetRunnerByName == nil {
		h.GetRunnerByName = srv.handleGetRunnerByName
	}

	if h.RemoveRunner == nil {
		h.RemoveRunner = srv.handleRemoveRunner
	}
}

// TODO: this uses ginkgo interface _only_ to support our current controller tests
func NewUnstarted(t ginkgo.GinkgoTInterface, handlers Handlers, options ...actionsServerOption) *actionsServer {
	mux := mux.NewRouter()
	s := httptest.NewUnstartedServer(mux)
	server := &actionsServer{
		Server: s,
	}

	t.Cleanup(func() {
		server.Close()
	})

	for _, option := range options {
		option(server)
	}

	handlers.defaults(server)

	// GitHub endpoints
	mux.HandleFunc("/orgs/{org}/actions/runners/registration-token", handlers.CreateRegistrationToken).Methods(http.MethodPost)
	mux.HandleFunc("/enterprises/{enterprise}/actions/runners/registration-token", handlers.CreateRegistrationToken).Methods(http.MethodPost)
	mux.HandleFunc("/repos/{org}/{repo}/actions/runners/registration-token", handlers.CreateRegistrationToken).Methods(http.MethodPost)
	mux.HandleFunc("/app/installations/{id}/access_tokens", handlers.CreateAccessToken).Methods(http.MethodPost)
	mux.HandleFunc("/actions/runner-registration", handlers.GetActionsServiceAdminConnection).Methods(http.MethodPost)

	// Actions service endpoints
	mux.HandleFunc(scaleSetEndpoint, handlers.CreateRunnerScaleSet).Methods(http.MethodPost)
	mux.HandleFunc(scaleSetEndpoint+"/{id:[0-9]+}", handlers.UpdateRunnerScaleSet).Methods(http.MethodPatch)
	mux.HandleFunc(scaleSetEndpoint+"/{id:[0-9]+}", handlers.DeleteRunnerScaleSet).Methods(http.MethodDelete)
	mux.HandleFunc(scaleSetEndpoint+"/{id:[0-9]+}", handlers.GetRunnerScaleSetByID).Methods(http.MethodGet)
	mux.HandleFunc(scaleSetEndpoint, handlers.GetRunnerScaleSetByName).Methods(http.MethodGet)
	mux.HandleFunc(scaleSetEndpoint+"/{sid:[0-9]+}/sessions", handlers.CreateMessageSession).Methods(http.MethodPost)
	mux.HandleFunc(scaleSetEndpoint+"/{sid:[0-9]+}/sessions/{id}", handlers.DeleteMessageSession).Methods(http.MethodDelete)
	mux.HandleFunc(scaleSetEndpoint+"/{sid:[0-9]+}/sessions/{id}", handlers.DeleteMessageSession).Methods(http.MethodPatch)
	mux.HandleFunc(scaleSetEndpoint+"/{sid:[0-9]+}/acquirejobs", handlers.AcquireJobs).Methods(http.MethodPost)

	server.Config.Handler = mux

	return server
}

type actionsServerOption func(*actionsServer)

func WithActionsToken(token string) actionsServerOption {
	return func(s *actionsServer) {
		s.token = token
	}
}

func WithOrg(organization, token string) actionsServerOption {
	return func(s *actionsServer) {
		s.db.orgs[organization] = &org{
			token: token,
			repos: make(map[string]*repo),
		}
	}
}

type actionsServer struct {
	*httptest.Server
	logger     logr.Logger
	token      string
	adminToken string

	db db
}

func (s *actionsServer) ConfigURLForOrg(org string) string {
	return s.URL + "/" + org
}

func DefaultActionsToken(t ginkgo.GinkgoTInterface) string {
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		Issuer:    "123",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(samplePrivateKey))
	require.NoError(t, err)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenString
}

const samplePrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgHXfRT9cv9UY9fAAD4+1RshpfSSZe277urfEmPfX3/Og9zJYRk//
CZrJVD1CaBZDiIyQsNEzjta7r4UsqWdFOggiNN2E7ZTFQjMSaFkVgrzHqWuiaCBf
/BjbKPn4SMDmTzHvIe7Nel76hBdCaVgu6mYCW5jmuSH5qz/yR1U1J/WJAgMBAAEC
gYARWGWsSU3BYgbu5lNj5l0gKMXNmPhdAJYdbMTF0/KUu18k/XB7XSBgsre+vALt
I8r4RGKApoGif8P4aPYUyE8dqA1bh0X3Fj1TCz28qoUL5//dA+pigCRS20H7HM3C
ojoqF7+F+4F2sXmzFNd1NgY5RxFPYosTT7OnUiFuu2IisQJBALnMLe09LBnjuHXR
xxR65DDNxWPQLBjW3dL+ubLcwr7922l6ZIQsVjdeE0ItEUVRjjJ9/B/Jq9VJ/Lw4
g9LCkkMCQQCiaM2f7nYmGivPo9hlAbq5lcGJ5CCYFfeeYzTxMqum7Mbqe4kk5lgb
X6gWd0Izg2nGdAEe/97DClO6VpKcPbpDAkBTR/JOJN1fvXMxXJaf13XxakrQMr+R
Yr6LlSInykyAz8lJvlLP7A+5QbHgN9NF/wh+GXqpxPwA3ukqdSqhjhWBAkBn6mDv
HPgR5xrzL6XM8y9TgaOlJAdK6HtYp6d/UOmN0+Butf6JUq07TphRT5tXNJVgemch
O5x/9UKfbrc+KyzbAkAo97TfFC+mZhU1N5fFelaRu4ikPxlp642KRUSkOh8GEkNf
jQ97eJWiWtDcsMUhcZgoB5ydHcFlrBIn6oBcpge5
-----END RSA PRIVATE KEY-----`

func (s *actionsServer) handleGetActionsServiceAdminConnection(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(auth, "Basic "), strings.HasPrefix(auth, "Bearer "):
	default:
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	type request struct {
		URL         string `json:"url"`
		RunnerEvent string `json:"runner_event"`
	}

	var body request
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.logger.Error(err, "Failed to decode request body")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	res := actions.ActionsServiceAdminConnection{
		ActionsServiceUrl: &s.Server.Config.Addr,
		AdminToken:        &s.adminToken,
	}
	writeJSON(w, &res)
}

func (s *actionsServer) handleCreateRegistrationToken(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Token     *string    `json:"token"`
		ExpiresAt *time.Time `json:"expires_at"`
	}

	registrationToken := strings.Repeat("a", 32)
	expiresAt := time.Now().Add(1 * time.Hour)

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, &response{
		Token:     &registrationToken,
		ExpiresAt: &expiresAt,
	})
}

func (s *actionsServer) handleCreateAccessToken(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	res := response{
		Token:     strings.Repeat("b", 32),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	writeJSON(w, &res)
}

func (s *actionsServer) handleCreateRunnerScaleSet(w http.ResponseWriter, r *http.Request) {
	var body actions.RunnerScaleSet
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.logger.Error(err, "Failed to read runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	body.Id = int(s.db.scaleSetIDCounter.Add(1))
	s.db.scaleSets.Store(body.Id, &body)
}

func (s *actionsServer) handleUpdateRunnerScaleSet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"]) // err should not occur since it is guarded by gorilla/mux
	_, ok := s.db.scaleSets.Load(id)
	if !ok {
		s.logger.Info("scale set is not found", "id", id)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	var body actions.RunnerScaleSet
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.logger.Error(err, "Failed to read runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	body.Id = int(id)
	s.db.scaleSets.Store(id, &body)
	writeJSON(w, &body)
}

func (s *actionsServer) handleDeleteRunnerScaleSet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"]) // err should not occur since it is guarded by gorilla/mux
	_, ok := s.db.scaleSets.LoadAndDelete(id)
	if !ok {
		s.logger.Info("Can't delete scale set that does not exist", "id", id)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	s.logger.Info("Runner scale set deleted", "id", id)
}

func (s *actionsServer) handleGetRunnerScaleSetByID(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"]) // err should not occur since it is guarded by gorilla/mux
	v, ok := s.db.scaleSets.Load(id)
	if !ok {
		s.logger.Info("Scale set not found", "id", id)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	writeJSON(w, v)
}

func (s *actionsServer) handleGetRunnerScaleSetByName(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.Atoi(r.URL.Query().Get("runnerGroupId"))
	if err != nil {
		s.logger.Error(err, "failed to parse runner group id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		s.logger.Error(fmt.Errorf("received empty name"), "Request does not contain name URL parameter")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	type response struct {
		Count           int                       `json:"count"`
		RunnerScaleSets []*actions.RunnerScaleSet `json:"value"`
	}

	var res response
	s.db.scaleSets.Range(func(key, value any) bool {
		v := value.(*actions.RunnerScaleSet)
		if v.RunnerGroupId != groupID {
			return true
		}
		if v.Name != name {
			return true
		}

		res.RunnerScaleSets = append(res.RunnerScaleSets, v)
		res.Count++
		return true
	})

	writeJSON(w, &res)
}

func (s *actionsServer) handleCreateMessageSession(w http.ResponseWriter, r *http.Request) {
	scaleSetID, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		s.logger.Error(err, "Failed to parse scale set id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	newID := uuid.New()
	s.db.org.repos["test"].scaleSets[scaleSetID].sessions[newID.String()] = true
	res := &actions.RunnerScaleSetSession{
		SessionId:               &newID,
		OwnerName:               "owner",
		RunnerScaleSet:          &actions.RunnerScaleSet{},
		MessageQueueUrl:         s.Server.Config.Addr,
		MessageQueueAccessToken: "token",
		Statistics:              &actions.RunnerScaleSetStatistic{},
	}

	writeJSON(w, res)
}

func (s *actionsServer) handleDeleteMessageSession(w http.ResponseWriter, r *http.Request) {
	scaleSetID, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil {
		s.logger.Error(err, "Failed to parse scale set id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	id := mux.Vars(r)["id"]

	delete(s.db.org.repos["test"].scaleSets[scaleSetID].sessions, id)
}

func (s *actionsServer) handleRefreshMessageSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_ = id
}

func (s *actionsServer) handleAcquireJobs(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_ = id
}

func (s *actionsServer) handleGetRunner(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_ = id
}

func (s *actionsServer) handleGetRunnerByName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		s.logger.Error(fmt.Errorf("received empty name"), "Request does not contain name URL parameter")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	type response struct {
		Count   int               `json:"count"`
		Runners []*actions.Runner `json:"value"`
	}

	var res response
	s.db.runners.Range(func(key, value any) bool {
		v := value.(*actions.Runner)
		if v.Name != name {
			return true
		}

		res.Runners = append(res.Runners, v)
		res.Count++
		return true
	})

	writeJSON(w, &res)
}

func (s *actionsServer) handleGetRunnerGroup(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	_ = id
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

type db struct {
	mu                sync.Mutex
	scaleSetIDCounter atomic.Int64
	scaleSets         sync.Map
	org               *org
	token             string
}

func newDB() *db {
	return &db{}
}

func (db *db) addRepo(org, repository string) {
	db.org.repos[repository] = &repo{
		scaleSets: make(map[int64]*scaleSet),
	}
}

func (db *db) addScaleSet(org, repository string, ss *scaleSet) {
	db.org.repos[repository].scaleSets[ss.id] = ss
}

type org struct {
	token string
	repos map[string]*repo
}

type repo struct {
	scaleSets map[int64]*scaleSet
}

type scaleSet struct {
	id       int64
	name     string
	sessions map[string]bool
	runners  map[int64]*runner
}

type runner struct {
	name string
}
