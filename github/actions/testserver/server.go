package testserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
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
	CreateRegistrationToken          http.HandlerFunc
	CreateAccessToken                http.HandlerFunc
	GetActionsServiceAdminConnection http.HandlerFunc
	CreateRunnerScaleSet             http.HandlerFunc
	UpdateRunnerScaleSet             http.HandlerFunc
	DeleteRunnerScaleSet             http.HandlerFunc
	GetRunnerScaleSetByID            http.HandlerFunc
	GetRunnerScaleSetByName          http.HandlerFunc
	CreateMessageSession             http.HandlerFunc
	DeleteMessageSession             http.HandlerFunc
	RefreshMessageSession            http.HandlerFunc
	AcquireJobs                      http.HandlerFunc
	GetMessage                       http.HandlerFunc
	DeleteMessage                    http.HandlerFunc
	GenerateJitRunnerConfig          http.HandlerFunc
	GetRunner                        http.HandlerFunc
	GetRunnerByName                  http.HandlerFunc
	RemoveRunner                     http.HandlerFunc
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
}

// TODO: this uses ginkgo interface _only_ to support our current controller tests
func NewUnstarted(t ginkgo.GinkgoTInterface, handlers Handlers, options ...actionsServerOption) *actionsServer {
	mux := mux.NewRouter()
	s := httptest.NewUnstartedServer(mux)
	server := &actionsServer{
		Server:                 s,
		registrationTokenStore: NewTokenStore(),
		githubTokenStore:       NewGitHubTokenStore(),
		actionsAdminTokenStore: NewActionsAdminTokenStore(),
		scaleSetStore:          NewScaleSetStore(),
		messageSessionStore:    NewMessageSessionStore(),
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
	mux.HandleFunc(scaleSetEndpoint+"/{ssid:[0-9]+}/sessions", handlers.CreateMessageSession).Methods(http.MethodPost)
	mux.HandleFunc(scaleSetEndpoint+"/{ssid:[0-9]+}/sessions/{id}", handlers.DeleteMessageSession).Methods(http.MethodDelete)
	mux.HandleFunc(scaleSetEndpoint+"/{ssid:[0-9]+}/sessions/{id}", handlers.DeleteMessageSession).Methods(http.MethodPatch)
	mux.HandleFunc(scaleSetEndpoint+"/{ssid:[0-9]+}/acquirejobs", handlers.AcquireJobs).Methods(http.MethodPost)

	server.Config.Handler = mux

	return server
}

type actionsServerOption func(*actionsServer)

type actionsServer struct {
	*httptest.Server
	logger logr.Logger

	registrationTokenStore *RegistrationTokenStore
	githubTokenStore       *GitHubTokenStore
	actionsAdminTokenStore *ActionsAdminTokenStore
	scaleSetStore          *ScaleSetStore
	messageSessionStore    *MessageSessionStore
}

func (s *actionsServer) ConfigURLForOrg(org string) string {
	return s.URL + "/" + org
}

func DefaultActionsTokenT(t *testing.T) string {
	token, err := DefaultActionsToken()
	require.NoError(t, err)
	return token
}

func DefaultActionsToken() (string, error) {
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		Issuer:    "testserver",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(samplePrivateKey))
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil

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
	const authType = "RemoteAuth "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, authType) {
		s.logger.Error(fmt.Errorf("remote auth not found in authorization header"), "Invalid auth header")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(auth, authType)

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

	if body.RunnerEvent != "registration" {
		s.logger.Error(fmt.Errorf("expected event 'registration'"), "Invalid runner event")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	data, err := s.registrationTokenStore.Get(token)
	if err != nil {
		s.logger.Error(err, "Failed to get registration token")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	s.logger.Info("Registration token used", "token", token, "data", data)

	adminToken, err := s.actionsAdminTokenStore.GenerateAdminToken(token)
	if err != nil {
		s.logger.Error(err, "Failed to generate admin token")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	res := actions.ActionsServiceAdminConnection{
		ActionsServiceUrl: &s.Server.Config.Addr,
		AdminToken:        &adminToken,
	}

	writeJSON(w, http.StatusOK, &res)
}

func (s *actionsServer) handleCreateRegistrationToken(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Token     *string    `json:"token"`
		ExpiresAt *time.Time `json:"expires_at"`
	}

	tokenData := RegistrationTokenData{
		Enterprise: mux.Vars(r)["enterprise"],
		Org:        mux.Vars(r)["org"],
		Repo:       mux.Vars(r)["repo"],
	}

	if err := s.registrationTokenStore.Create(&tokenData); err != nil {
		s.logger.Error(err, "Failed to create registration token")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, &response{
		Token:     &tokenData.ID,
		ExpiresAt: &tokenData.ExpiresAt,
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

	writeJSON(w, http.StatusOK, &res)
}

func (s *actionsServer) handleCreateRunnerScaleSet(w http.ResponseWriter, r *http.Request) {
	var body actions.RunnerScaleSet
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.logger.Error(err, "Failed to read runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	s.scaleSetStore.Create(&body)
	writeJSON(w, http.StatusOK, &body)
}

func (s *actionsServer) handleUpdateRunnerScaleSet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"]) // err should not occur since it is guarded by gorilla/mux

	var body actions.RunnerScaleSet
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.logger.Error(err, "Failed to read runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	body.Id = id
	err := s.scaleSetStore.Update(&body)
	if err != nil {
		s.logger.Error(err, "Failed to update runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, &body)
}

func (s *actionsServer) handleDeleteRunnerScaleSet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	if err := s.scaleSetStore.Delete(id); err != nil {
		s.logger.Error(err, "Failed to delete runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
}

func (s *actionsServer) handleGetRunnerScaleSetByID(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"]) // err should not occur since it is guarded by gorilla/mux
	scaleSet, err := s.scaleSetStore.GetByID(id)
	if err != nil {
		s.logger.Error(err, "Failed to get runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, scaleSet)
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

	scaleSets, err := s.scaleSetStore.GetByNameAndGroupID(name, groupID)
	if err != nil {
		s.logger.Error(err, "Failed to get runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	res := response{
		Count:           len(scaleSets),
		RunnerScaleSets: scaleSets,
	}

	writeJSON(w, http.StatusOK, &res)
}

func (s *actionsServer) handleCreateMessageSession(w http.ResponseWriter, r *http.Request) {
	scaleSetID, err := strconv.Atoi(mux.Vars(r)["ssid"])
	if err != nil {
		s.logger.Error(err, "Failed to parse scale set id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	scaleSet, err := s.scaleSetStore.GetByID(scaleSetID)
	if err != nil {
		s.logger.Error(err, "Failed to get runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	newID := uuid.New()
	s.messageSessionStore.Create(newID.String(), scaleSetID)
	res := &actions.RunnerScaleSetSession{
		SessionId:               &newID,
		OwnerName:               "owner",
		RunnerScaleSet:          scaleSet,
		MessageQueueUrl:         s.Server.Config.Addr,
		MessageQueueAccessToken: newID.String(),
		Statistics:              &actions.RunnerScaleSetStatistic{},
	}

	writeJSON(w, http.StatusCreated, res)
}

func (s *actionsServer) handleDeleteMessageSession(w http.ResponseWriter, r *http.Request) {
	scaleSetID, err := strconv.Atoi(mux.Vars(r)["ssid"])
	if err != nil {
		s.logger.Error(err, "Failed to parse scale set id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	sessionID, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		s.logger.Error(err, "Failed to parse session id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	ssid, err := s.messageSessionStore.Get(sessionID.String())
	if err != nil {
		s.logger.Error(err, "Failed to get session")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if ssid != scaleSetID {
		s.logger.Error(err, "Session does not belong to scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	s.messageSessionStore.Delete(sessionID.String())
	w.WriteHeader(http.StatusNoContent)
}

func (s *actionsServer) handleRefreshMessageSession(w http.ResponseWriter, r *http.Request) {
	scaleSetID, err := strconv.Atoi(mux.Vars(r)["ssid"])
	if err != nil {
		s.logger.Error(err, "Failed to parse scale set id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	sessionID, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		s.logger.Error(err, "Failed to parse session id")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	ssid, err := s.messageSessionStore.Get(sessionID.String())
	if err != nil {
		s.logger.Error(err, "Failed to get session")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if ssid != scaleSetID {
		s.logger.Error(err, "Session does not belong to scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	scaleSet, err := s.scaleSetStore.GetByID(scaleSetID)
	if err != nil {
		s.logger.Error(err, "Failed to get runner scale set")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	newID := uuid.New()
	s.messageSessionStore.Create(newID.String(), scaleSetID)
	res := &actions.RunnerScaleSetSession{
		SessionId:               &newID,
		OwnerName:               "owner",
		RunnerScaleSet:          scaleSet,
		MessageQueueUrl:         s.Server.Config.Addr,
		MessageQueueAccessToken: newID.String(),
		Statistics:              &actions.RunnerScaleSetStatistic{},
	}

	writeJSON(w, http.StatusCreated, res)

}

func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
