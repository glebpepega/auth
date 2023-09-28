package server

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/glebpepega/auth/internal/db"
	"github.com/glebpepega/auth/internal/jwtaccess"
	"github.com/google/uuid"
)

type server struct {
	r  *http.ServeMux
	db *db.DB
}

func New() *server {
	return &server{}
}

func (s *server) configure() {
	database := db.New()
	s.db = database
	database.Connect()
	r := http.NewServeMux()
	s.r = r
}

func (s *server) Start() {
	s.configure()
	s.r.HandleFunc("/jwt", s.jwtHandler)
	s.r.HandleFunc("/refresh", s.refreshHandler)
	log.Fatal(http.ListenAndServe(":8080", s.r))
}

func (s *server) jwtHandler(w http.ResponseWriter, r *http.Request) {
	if guid := r.URL.Query().Get("guid"); guid == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("requires non-nil guid query param"))
	} else {
		accessToken, err := jwtaccess.Generate(guid)
		if err != nil {
			log.Fatal(err)
		}
		refreshToken := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))
		if err := s.db.InsertRefresh(guid, refreshToken); err != nil {
			log.Fatal(err)
		}
		SetRefreshCookie(w, refreshToken)
		body := fmt.Sprintf(`{"accessToken":"%s", "refreshToken":"%s"}`, accessToken, refreshToken)
		w.Write([]byte(body))
	}
}

func (s *server) refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if headerParts := strings.Split(r.Header.Get("Token"), " "); len(headerParts) < 2 && headerParts[0] != "Bearer" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing access token or wrong access token format"))
		return
	} else {
		claims, err := jwtaccess.Parse(headerParts[1])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		} else {
			cookie, err := r.Cookie("refreshToken")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("missing refreshToken cookie"))
				return
			}
			oldRefresh := cookie.Value
			guid, err := s.db.FindRefresh(oldRefresh)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("invalid refresh token"))
				return
			}
			if guid != claims["guid"] {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("access and refresh tokens are incompatible"))
				return
			}
			newAccess, err := jwtaccess.Generate(guid)
			if err != nil {
				log.Fatal(err)
			}
			newRefresh, err := s.db.UpdateRefresh(oldRefresh)
			if err != nil {
				log.Fatal(err)
			}
			SetRefreshCookie(w, newRefresh)
			body := fmt.Sprintf(`{"accessToken":"%s", "refreshToken":"%s"}`, newAccess, newRefresh)
			w.Write([]byte(body))
		}
	}
}

func SetRefreshCookie(w http.ResponseWriter, refreshToken string) {
	cookie := http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		Expires:  time.Now().Add(time.Hour * 24),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
}
