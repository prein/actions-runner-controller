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
func New(t ginkgo.GinkgoTInterface, handler http.Handler, options ...actionsServerOption) *actionsServer {
	s := NewUnstarted(t, handler, options...)
	s.Start()
	return s
}

// TODO: this uses ginkgo interface _only_ to support our current controller tests
func NewUnstarted(t ginkgo.GinkgoTInterface, handler http.Handler, options ...actionsServerOption) *actionsServer {
	s := httptest.NewUnstartedServer(handler)
	server := &actionsServer{
		Server: s,
	}
	t.Cleanup(func() {
		server.Close()
	})

	for _, option := range options {
		option(server)
	}

	mux := mux.NewRouter()
	// GitHub endpoints
	mux.HandleFunc("/orgs/{org}/actions/runners/registration-token", server.handleCreateRegistrationToken).Methods(http.MethodPost)
	mux.HandleFunc("/enterprises/{enterprise}/actions/runners/registration-token", server.handleCreateRegistrationToken).Methods(http.MethodPost)
	mux.HandleFunc("/repos/{org}/{repo}/actions/runners/registration-token", server.handleCreateRegistrationToken).Methods(http.MethodPost)
	mux.HandleFunc("/app/installations/{id}/access_tokens", server.handleCreateAccessToken).Methods(http.MethodPost)
	mux.HandleFunc("/actions/runner-registration", server.handleGetActionsServiceAdminConnection).Methods(http.MethodPost)

	// Actions service endpoints
	mux.HandleFunc(scaleSetEndpoint, server.handleCreateRunnerScaleSet).Methods(http.MethodPost)
	mux.HandleFunc(scaleSetEndpoint+"/{id:[0-9]+}", server.handleUpdateRunnerScaleSet).Methods(http.MethodPatch)
	mux.HandleFunc(scaleSetEndpoint+"/{id:[0-9]+}", server.handleDeleteRunnerScaleSet).Methods(http.MethodDelete)
	mux.HandleFunc(scaleSetEndpoint+"/{id:[0-9]+}", server.handleGetRunnerScaleSetByID).Methods(http.MethodGet)
	mux.HandleFunc(scaleSetEndpoint, server.handleGetRunnerScaleSetByName).Methods(http.MethodGet)
	mux.HandleFunc(scaleSetEndpoint+"/{id:[0-9]+}/sessions", server.handleCreateMessageSession).Methods(http.MethodPost)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// handle getRunnerRegistrationToken
		if strings.HasSuffix(r.URL.Path, "/runners/registration-token") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"token":"token"}`))
			return
		}

		// handle getActionsServiceAdminConnection
		if strings.HasSuffix(r.URL.Path, "/actions/runner-registration") {
			if server.token == "" {
				server.token = DefaultActionsToken(t)
			}

			w.Write([]byte(`{"url":"` + s.URL + `/tenant/123/","token":"` + server.token + `"}`))
			return
		}

		handler.ServeHTTP(w, r)
	})

	server.Config.Handler = h

	return server
}

type actionsServerOption func(*actionsServer)

func WithActionsToken(token string) actionsServerOption {
	return func(s *actionsServer) {
		s.token = token
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
	// id := mux.Vars(r)["id"]
	uuid := uuid.New()
	res := &actions.RunnerScaleSetSession{
		SessionId:               &uuid,
		OwnerName:               "owner",
		RunnerScaleSet:          &actions.RunnerScaleSet{},
		MessageQueueUrl:         s.Server.Config.Addr,
		MessageQueueAccessToken: "token",
		Statistics:              &actions.RunnerScaleSetStatistic{},
	}

	writeJSON(w, res)
}

func (s *actionsServer) GetRunner(w http.ResponseWriter, r *http.Request) {
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
	orgs              map[string]*org
}

func newDB() *db {
	return &db{
		orgs: make(map[string]*org),
	}
}

func (db *db) addOrg(name string) {
	db.orgs[name] = &org{
		repos: make(map[string]*repo),
	}
}

func (db *db) addRepo(org, repository string) {
	db.orgs[org].repos[repository] = &repo{
		scaleSets: make(map[int64]*scaleSet),
	}
}

func (db *db) addScaleSet(org, repository string, ss *scaleSet) {
	db.orgs[org].repos[repository].scaleSets[ss.id] = ss
}

type org struct {
	repos map[string]*repo
}

type repo struct {
	scaleSets map[int64]*scaleSet
}

type scaleSet struct {
	id      int64
	name    string
	runners map[int64]*runner
}

type runner struct {
	name string
}
