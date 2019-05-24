package main // import "github.com/finkf/pcwauth"

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/finkf/pcwgo/api"
	"github.com/finkf/pcwgo/db"
	"github.com/finkf/pcwgo/service"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

var (
	listen   string
	cert     string
	key      string
	dsn      string
	pocoweb  string
	profiler string
	users    string
	debug    bool
	version  api.Version
	vonce    sync.Once
	client   *http.Client
)

func init() {
	flag.StringVar(&listen, "listen", ":8080", "set listening host")
	flag.StringVar(&cert, "cert", "", "set cert file (no tls if omitted)")
	flag.StringVar(&key, "key", "", "set key file (no tls if omitted)")
	flag.StringVar(&dsn, "dsn", "", "set mysql connection DSN (user:pass@proto(host)/dbname)")
	flag.StringVar(&pocoweb, "pocoweb", "", "set host of pocoweb")
	flag.StringVar(&profiler, "profiler", "", "set host of pcwprofiler")
	flag.StringVar(&users, "users", "", "set host of pcwusers")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	client = &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost: 1024,
		TLSHandshakeTimeout: 0 * time.Second,
	}}
}

func must(err error) {
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

func main() {
	// flags
	flag.Parse()
	if debug {
		log.SetLevel(log.DebugLevel)
	}
	// database
	must(service.Init(dsn))
	defer service.Close()
	// login
	http.HandleFunc(api.LoginURL,
		service.WithLog(service.WithMethods(
			http.MethodGet, service.WithAuth(getLogin()),
			http.MethodPost, postLogin())))
	http.HandleFunc(api.LogoutURL, service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(getLogout()))))
	// user management
	http.HandleFunc("/users", service.WithLog(service.WithMethods(
		http.MethodPost, service.WithAuth(root(forward(users))),
		http.MethodGet, service.WithAuth(root(forward(users))))))
	http.HandleFunc("/users/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(rootOrSelf(forward(users))),
		http.MethodPut, service.WithAuth(rootOrSelf(forward(users))),
		http.MethodDelete, service.WithAuth(rootOrSelf(forward(users))))))
	// book management
	http.HandleFunc("/books", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(forward(pocoweb)),
		http.MethodPost, service.WithAuth(forward(pocoweb)))))
	http.HandleFunc("/books/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(service.WithProject(projectOwner(forward(pocoweb)))),
		http.MethodPost, service.WithAuth(service.WithProject(projectOwner(forward(pocoweb)))),
		http.MethodDelete, service.WithAuth(service.WithProject(projectOwner(forward(pocoweb)))))))
	// profiling
	http.HandleFunc("/profile/languages", service.WithLog(service.WithMethods(
		http.MethodGet, forward(profiler))))
	http.HandleFunc("/profile/jobs/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(forward(profiler)))))
	http.HandleFunc("/profile/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(service.WithProject(projectOwner(forward(profiler)))),
		http.MethodPost, service.WithAuth(service.WithProject(projectOwner(forward(profiler)))))))
	// version
	http.HandleFunc(api.VersionURL, service.WithMethods(
		http.MethodGet, getVersion()))
	log.Infof("listening on %s", listen)
	if cert != "" && key != "" {
		must(http.ListenAndServeTLS(listen, cert, key, nil))
	} else {
		must(http.ListenAndServe(listen, nil))
	}
}

func root(f service.HandlerFunc) service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		log.Debugf("root: %s", d.Session.User)
		if !d.Session.User.Admin {
			service.ErrorResponse(w, http.StatusForbidden,
				"only root allowed to access: %s", d.Session.User)
			return
		}
		f(w, r, d)
	}
}

func rootOrSelf(f service.HandlerFunc) service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		log.Debugf("rootOrSelf: %s", d.Session.User)
		if !d.Session.User.Admin && int64(d.ID) != d.Session.User.ID {
			service.ErrorResponse(w, http.StatusForbidden,
				"not allowed to access: %s", d.Session.User)
			return
		}
		f(w, r, d)
	}
}

func projectOwner(f service.HandlerFunc) service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		log.Debugf("projectOwner: id: %d, user: %s, owner: %s",
			d.Project.ProjectID, d.Session.User, d.Project.Owner)
		if d.Session.User.ID != d.Project.Owner.ID {
			service.ErrorResponse(w, http.StatusForbidden,
				"not allowed to access project: %d", d.Project.ProjectID)
			return
		}
		f(w, r, d)
	}
}

func postLogin() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		var data api.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			service.ErrorResponse(w, http.StatusBadRequest,
				"cannot login: invalid login data")
			return
		}

		user, found, err := db.FindUserByEmail(service.Pool(), data.Email)
		if err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot login: %v", err)
			return
		}
		if !found {
			service.ErrorResponse(w, http.StatusNotFound,
				"cannot login: no such user: %s", data.Email)
			return
		}

		log.Infof("login request for user: %s", user)
		if err = db.AuthenticateUser(service.Pool(), user, data.Password); err != nil {
			service.ErrorResponse(w, http.StatusForbidden,
				"cannot login: invalid password: %v", err)
			return
		}
		if err = db.DeleteSessionByUserID(service.Pool(), user.ID); err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot login: cannot delete session: %v", err)
			return
		}

		s, err := db.InsertSession(service.Pool(), user)
		log.Debugf("login: new session: %s", s)
		if err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot login: cannot insert session: %v", err)
			return
		}
		service.JSONResponse(w, s)
	}
}

func getLogin() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		service.JSONResponse(w, d.Session)
	}
}

func getLogout() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		log.Debugf("logout session: %s", d.Session)
		service.RemoveSession(d.Session)
		if err := db.DeleteSessionByUserID(service.Pool(), d.Session.User.ID); err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot logout: cannot delete session: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func forward(base string) service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		url := forwardURL(r.URL.String(), base, d)
		log.Infof("forwarding [%s] %s -> %s", r.Method, r.URL.String(), url)
		switch r.Method {
		case http.MethodGet:
			res, err := client.Get(url)
			forwardRequest(w, url, res, err)
		case http.MethodPost:
			res, err := client.Post(url, r.Header.Get("Content-Type"), r.Body)
			forwardRequest(w, url, res, err)
		case http.MethodDelete:
			req, err := http.NewRequest(http.MethodDelete, url, nil)
			if err != nil {
				service.ErrorResponse(w, http.StatusInternalServerError,
					"cannot forward: %v", err)
				return
			}
			res, err := client.Do(req)
			forwardRequest(w, url, res, err)
		default:
			service.ErrorResponse(w, http.StatusBadRequest,
				"cannot forward: invalid method: %s", r.Method)
		}
	}
}

func forwardRequest(w http.ResponseWriter, url string, res *http.Response, err error) {
	if err != nil {
		service.ErrorResponse(w, http.StatusInternalServerError,
			"cannot forward request: %s", err)
		return
	}
	defer res.Body.Close()
	log.Debugf("forwarding: %s (Content-Length: %d)", res.Status, res.ContentLength)
	for k, v := range res.Header {
		for i := range v {
			w.Header().Add(k, v[i])
		}
	}
	w.WriteHeader(res.StatusCode)
	// copy content
	n, err := io.Copy(w, res.Body)
	if err != nil {
		service.ErrorResponse(w, http.StatusInternalServerError,
			"cannot forward request: %v", err)
		return
	}
	log.Infof("forwarded %d bytes", n)
}

// just handle api-version once
func getVersion() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		vonce.Do(func() {
			url := pocoweb + "/api-version"
			res, err := client.Get(url)
			if err != nil {
				log.Errorf("cannot get api version: %s", err)
				return
			}
			defer res.Body.Close()
			if err := json.NewDecoder(res.Body).Decode(&version); err != nil {
				log.Errorf("cannot get api version: cannot decode json: %s", err)
			}
		})
		service.JSONResponse(w, version)
	}
}

func forwardURL(url, base string, d *service.Data) string {
	if d == nil || d.Session == nil {
		return fmt.Sprintf("%s%s", base, url)
	}
	i := strings.LastIndex(url, "?")
	if i == -1 {
		return fmt.Sprintf("%s%s?userid=%d", base, url, d.Session.User.ID)
	}
	return fmt.Sprintf("%s%s&userid=%d", base, url, d.Session.User.ID)
}
