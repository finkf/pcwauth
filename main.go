package main // import "github.com/finkf/pcwauth"

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
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
	host     string
	cert     string
	key      string
	dsn      string
	pocoweb  string
	profiler string
	rName    string
	rPass    string
	rEmail   string
	rInst    string
	debug    bool
	version  api.Version
	vonce    sync.Once
	client   *http.Client
)

func init() {
	flag.StringVar(&host, "listen", ":8080", "set listening host")
	flag.StringVar(&cert, "cert", "", "set cert file (no tls if omitted)")
	flag.StringVar(&key, "key", "", "set key file (no tls if omitted)")
	flag.StringVar(&dsn, "dsn", "", "set mysql connection DSN (user:pass@proto(host)/dbname)")
	flag.StringVar(&pocoweb, "pocoweb", "", "set host of pocoweb")
	flag.StringVar(&profiler, "profiler", "", "set host of profiler")
	flag.StringVar(&rName, "root-name", "", "user name for the root account")
	flag.StringVar(&rEmail, "root-email", "", "email for the root account")
	flag.StringVar(&rPass, "root-password", "", "password for the root account")
	flag.StringVar(&rInst, "root-institute", "", "institute for the root account")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	client = &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost: 1024,
		TLSHandshakeTimeout: 0 * time.Second,
	}}
}

type request struct {
	r  *http.Request // request
	s  api.Session   // session
	p  *db.Project   // the project
	d  interface{}   // post or put data
	id int64         // active ID
}

func must(err error) {
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

func insertRoot() error {
	root := api.User{
		Name:      rName,
		Email:     rEmail,
		Institute: rInst,
		Admin:     true,
	}
	_, found, err := db.FindUserByEmail(service.Pool(), root.Email)
	if err != nil {
		return fmt.Errorf("cannot find user %s: %v", root, err)
	}
	if found { // root allready exists
		return nil
	}
	if err = db.InsertUser(service.Pool(), &root); err != nil {
		return fmt.Errorf("cannot create user %s: %v", root, err)
	}
	if err := db.SetUserPassword(service.Pool(), root, rPass); err != nil {
		return fmt.Errorf("cannot set password for %s: %v", root, err)
	}
	return nil
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
	// root
	if rName != "" && rEmail != "" && rPass != "" {
		must(insertRoot())
	}
	// login
	http.HandleFunc(api.LoginURL,
		service.WithLog(service.WithMethods(
			http.MethodGet, service.WithAuth(getLogin()),
			http.MethodPost, postLogin())))
	http.HandleFunc(api.LogoutURL, service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(getLogout()))))
	// user management
	http.HandleFunc("/users", service.WithLog(service.WithMethods(
		http.MethodPost, service.WithAuth(root(withPostUser(postUser()))),
		http.MethodGet, service.WithAuth(root(getAllUsers())))))
	http.HandleFunc("/users/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(withUserID(rootOrSelf(getUser()))),
		http.MethodPut, service.WithAuth(withPostUser(withUserID(rootOrSelf(putUser())))),
		http.MethodDelete, service.WithAuth(withUserID(rootOrSelf(deleteUser()))))))
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
	http.HandleFunc("/profile/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithProject(projectOwner(forward(profiler))))))
	// version
	http.HandleFunc(api.VersionURL, service.WithMethods(
		http.MethodGet, getVersion()))
	log.Infof("listening on %s", host)
	if cert != "" && key != "" {
		must(http.ListenAndServeTLS(host, cert, key, nil))
	} else {
		must(http.ListenAndServe(host, nil))
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
		log.Debugf("projectOwner: user: %s; owner: %s", d.Session.User, d.Project.Owner)
		if d.Session.User.ID != d.Project.Owner.ID {
			service.ErrorResponse(w, http.StatusForbidden,
				"not allowed to access project: %d", d.Project.ProjectID)
			return
		}
		f(w, r, d)
	}
}

func withUserID(f service.HandlerFunc) service.HandlerFunc {
	re := regexp.MustCompile(`/users/(\d+)`)
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		if err := service.ParseIDs(r.URL.String(), re, &d.ID); err != nil {
			service.ErrorResponse(w, http.StatusNotFound,
				"invalid user id: %v", err)
			return
		}
		log.Debugf("withUserID: %d", d.ID)
		f(w, r, d)
	}
}

func withPostUser(f service.HandlerFunc) service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		var data api.CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			service.ErrorResponse(w, http.StatusBadRequest,
				"cannot read user: invalid data: %v", err)
			return
		}
		log.Debugf("withPostUser: %s", data.User)
		d.Post = data
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

func getAllUsers() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		log.Debugf("get all users")
		users, err := db.FindAllUsers(service.Pool())
		if err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot list users: %v", err)
			return
		}
		service.JSONResponse(w, api.Users{Users: users})
	}
}

func getUser() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		u, found, err := db.FindUserByID(service.Pool(), int64(d.ID))
		if err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot get user: %v", err)
			return
		}
		if !found {
			service.ErrorResponse(w, http.StatusNotFound,
				"cannot get user: not found")
			return
		}
		log.Printf("get user: %s", u)
		service.JSONResponse(w, u)
	}
}

func postUser() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		t := db.NewTransaction(service.Pool().Begin())
		u := d.Post.(api.CreateUserRequest)
		t.Do(func(dtb db.DB) error {
			if err := db.InsertUser(dtb, &u.User); err != nil {
				return err
			}
			if err := db.SetUserPassword(dtb, u.User, u.Password); err != nil {
				return fmt.Errorf("cannot set password: %v", err)
			}
			return nil
		})
		if err := t.Done(); err != nil {
			service.ErrorResponse(w, http.StatusBadRequest, "cannot create user: %v", err)
			return
		}
		service.JSONResponse(w, u.User)
	}
}

func putUser() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		// this must not fail
		u := d.Post.(api.CreateUserRequest)
		t := db.NewTransaction(service.Pool().Begin())
		t.Do(func(dtb db.DB) error {
			if err := db.UpdateUser(dtb, u.User); err != nil {
				return err
			}
			if u.Password == "" { // do not update emtpy passwords
				return nil
			}
			if err := db.SetUserPassword(dtb, u.User, u.Password); err != nil {
				return fmt.Errorf("cannot set password: %v", err)
			}
			return nil
		})
		if err := t.Done(); err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot update user: %v", err)
			return
		}
		service.JSONResponse(w, u.User)
	}
}

func deleteUser() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		// TODO: delete all projects of the particular user
		if err := db.DeleteUserByID(service.Pool(), int64(d.ID)); err != nil {
			service.ErrorResponse(w, http.StatusNotFound,
				"cannot delete user: %v", err)
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
	if !service.IsValidStatus(res, http.StatusOK, http.StatusCreated) {
		io.Copy(ioutil.Discard, res.Body) // drain body
		service.ErrorResponse(w, http.StatusInternalServerError,
			"cannot forward request: invalid response: %s %d", res.Status, res.StatusCode)
		return
	}
	log.Debugf("got answer from forward request")
	// copy header
	for k, v := range res.Header {
		for i := range v {
			w.Header().Add(k, v[i])
		}
	}
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
// TODO: use once
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
