package main // import "github.com/finkf/pcwauth"

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/finkf/pcwgo/api"
	"github.com/finkf/pcwgo/database"
	"github.com/finkf/pcwgo/database/project"
	"github.com/finkf/pcwgo/database/session"
	"github.com/finkf/pcwgo/database/user"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

var (
	db      *sql.DB
	host    string
	cert    string
	key     string
	dbpass  string
	dbname  string
	dbhost  string
	dbuser  string
	pocoweb string
	debug   bool
	root    = user.User{
		Name:      "root",
		Email:     "root@example.com",
		Institute: "CIS",
		Admin:     true,
	}
	version api.Version
)

func init() {
	flag.StringVar(&host, "listen", ":8080", "set listening host")
	flag.StringVar(&cert, "cert", "", "set cert file (no tls if omitted)")
	flag.StringVar(&key, "key", "", "set key file (no tls if omitted)")
	flag.StringVar(&dbpass, "db", "", "set mysql connection DSN (user:pass@proto(host)/dbname)")
	flag.StringVar(&pocoweb, "pocoweb", "", "set host of pocoweb")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
}

type request struct {
	r  *http.Request   // request
	s  session.Session // session
	p  project.Project // the project
	d  interface{}     // post or put data
	id int64           // active ID
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func dbConnectionString() string {
	return dbuser + ":" + dbpass + "@(" + dbhost + ")/" + dbname
}

func setupDatabase() error {
	var err error
	db, err = sql.Open("mysql", "pocoweb:pocoweb1998@(172.18.0.1)/pocoweb")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(100)
	db.SetConnMaxLifetime(100)
	db.SetMaxIdleConns(10)
	return nil
}

func setupLogging() {
	if debug {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
	flag.Parse()
	setupLogging()
	must(setupDatabase())
	defer db.Close()
	// login
	http.HandleFunc(api.LoginURL, logURL(apih(apiGetPost(
		apiAuth(getLogin),
		postLogin))))
	http.HandleFunc(api.LogoutURL, logURL(apih(apiGetPost(
		apiAuth(getLogout),
		postLogin))))
	// user management
	http.HandleFunc("/users", logURL(apih(apiAuth(onlyRoot(
		apiGetPost(
			getUser,
			postUser))))))
	http.HandleFunc("/users/", logURL(apih(apiAuth(withUserID(rootOrSelf(
		apiGetPutDelete(
			getUser,
			withUser(putUser),
			deleteUser)))))))
	// book management
	http.HandleFunc("/books", logURL(apih(apiAuth(cached(
		apiGetPost(
			forwardGetRequest,
			onlyRoot(forwardPostRequest)))))))
	http.HandleFunc("/books/", logURL(apih(apiAuth(cached(withProject(onlyProjectOwner(
		apiGetPostDelete(
			forwardGetRequest,
			forwardPostRequest,
			forwardDeleteRequest))))))))
	// misc
	http.HandleFunc(api.VersionURL, apih(apiGet(getVersion)))
	http.HandleFunc("/profiler-languages", logURL(apih(cached(
		apiGet(forwardGetRequest)))))

	log.Infof("listening on %s", host)
	if cert != "" && key != "" {
		must(http.ListenAndServeTLS(host, cert, key, nil))
	} else {
		must(http.ListenAndServe(host, nil))
	}
}

type hf func(http.ResponseWriter, *http.Request)

func logURL(f hf) hf {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Infof("handling %s %s", r.Method, r.URL)
		f(w, r)
		log.Debugf("handled %s %s [%v]", r.Method, r.URL, w.Header().Get("Content-Type"))
	}
}

type apifunc func(*request) (interface{}, error)

func apih(f apifunc) hf {
	return func(w http.ResponseWriter, r *http.Request) {
		req := request{r: r}
		res, err := f(&req)
		if err != nil {
			apiError(w, err)
			return
		}
		if data, ok := res.([]byte); ok {
			apiBytes(w, data)
			return
		}
		apiJSON(w, res)
	}
}

func apiJSON(w http.ResponseWriter, data interface{}) {
	if data == nil {
		return
	}
	w.Header()["Content-Type"] = []string{"application/json"}
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// There is no way to handle this error
		// other than to log it.
		log.Errorf("cannot encode json: %v", err)
	}
}

func apiBytes(w http.ResponseWriter, data []byte) {
	if data == nil {
		return
	}
	// bytes are still JSON encoded data
	w.Header()["Content-Type"] = []string{"application/json"}
	if _, err := w.Write(data); err != nil {
		// There is no way to handle this error
		// other than to log it.
		log.Errorf("cannot write data: %v", err)
	}
}

// err must not be nil
func apiError(w http.ResponseWriter, err error) {
	switch t := err.(type) {
	case api.ErrorResponse:
		writeAPIError(w, t)
	default:
		writeAPIError(w, internalServerError(err.Error()))
	}
}

func writeAPIError(w http.ResponseWriter, err api.ErrorResponse) {
	log.Errorf("%s [%d %s]", err.Cause, err.StatusCode, err.Status)
	http.Error(w, err.Error(), err.StatusCode)
	apiJSON(w, err)
}

func apiGetPostPutDelete(get, post, put, delete apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		switch r.r.Method {
		case http.MethodGet:
			return get(r)
		case http.MethodPost:
			return post(r)
		case http.MethodPut:
			return put(r)
		case http.MethodDelete:
			return delete(r)
		default:
			return nil, methodNotAllowed("invalid method: %s", r.r.Method)
		}
	}
}

func apiGetPostDelete(get, post, delete apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		switch r.r.Method {
		case http.MethodGet:
			return get(r)
		case http.MethodPost:
			return post(r)
		case http.MethodDelete:
			return delete(r)
		default:
			return nil, methodNotAllowed("invalid method: %s", r.r.Method)
		}
	}
}

func apiGetPutDelete(get, put, delete apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		switch r.r.Method {
		case http.MethodGet:
			return get(r)
		case http.MethodPut:
			return put(r)
		case http.MethodDelete:
			return delete(r)
		default:
			return nil, methodNotAllowed("invalid method: %s", r.r.Method)
		}
	}
}

func apiGetPost(get, post apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		switch r.r.Method {
		case http.MethodGet:
			return get(r)
		case http.MethodPost:
			return post(r)
		default:
			return nil, methodNotAllowed("invalid method: %s", r.r.Method)
		}
	}
}

func apiPost(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		if r.r.Method != http.MethodPost {
			return nil, methodNotAllowed("invalid method: expected POST")
		}
		return f(r)
	}
}

func apiGet(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		if r.r.Method != http.MethodGet {
			return nil, methodNotAllowed("invalid method: expected GET")
		}
		return f(r)
	}
}

func apiAuth(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		if len(r.r.URL.Query()["auth"]) != 1 {
			return nil, forbidden("missing auth parameter")
		}
		auth := r.r.URL.Query()["auth"][0]
		val, err := authCache.Get(auth)
		if err != nil {
			return nil, err
		}
		r.s = val.(session.Session)
		log.Infof("user %s authenticated with: %s", r.s.User, r.s.Auth)
		return f(r)
	}
}

func onlyRoot(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		if !r.s.User.Admin {
			return nil, forbidden("not an admin account: %s", r.s.User)
		}
		return f(r)
	}
}

func rootOrSelf(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		log.Debugf("rootOrSelf: user: %s; id: %d", r.s.User, r.id)
		if !r.s.User.Admin && r.id != r.s.User.ID {
			return nil, forbidden("user %s: cannot access user-id: %d",
				r.s.User, r.id)
		}
		return f(r)
	}
}

func onlyProjectOwner(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		log.Debugf("onlyProjectOwner: user: %s; owner-id: %d", r.s.User, r.p.Owner.ID)
		if r.s.User.ID != r.p.Owner.ID {
			return nil, forbidden("user %s: cannot access project-id: %d", r.s.User, r.p.ID)
		}
		return f(r)
	}
}

var restProjectIDRegex = regexp.MustCompile(`/books/(\d+).*`)

func withProject(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		url := r.r.URL.String()
		m := restUserIDRegex.FindStringSubmatch(url)
		if m == nil || len(m) != 2 {
			return nil, notFound("no such url: %s", url)
		}
		id, _ := strconv.ParseInt(m[1], 10, 64)
		p, err := getProjectCache(id)
		if err != nil {
			return nil, internalServerError("cannot load project-id: %d: %v", id, err)
		}
		r.p = p
		return f(r)
	}
}

var restUserIDRegex = regexp.MustCompile(`/users/(\d+)?`)

func withUserID(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		url := r.r.URL.String()
		m := restUserIDRegex.FindStringSubmatch(url)
		if m == nil || len(m) != 2 {
			return nil, notFound("no such url: %s", url)
		}
		r.id, _ = strconv.ParseInt(m[1], 10, 64)
		log.Debugf("with user-id: %d", r.id)
		return f(r)
	}
}

func withUser(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		var data api.CreateUserRequest
		if err := json.NewDecoder(r.r.Body).Decode(&data); err != nil {
			return nil, badRequest("invalid post data: %v", err)
		}
		r.d = data
		return f(r)
	}
}

func cached(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		if r.r.Method == http.MethodGet {
			return getAPICache(r, f)
		}
		// Post, Put or Delete: clear all caches
		log.Debugf("%s: purging caches", r.r.Method)
		purgeAuthCache()
		purgeProjectCache()
		purgeAPICache(r)
		return f(r)
	}
}

func postLogin(r *request) (interface{}, error) {
	var data api.LoginRequest
	if err := json.NewDecoder(r.r.Body).Decode(&data); err != nil {
		return nil, badRequest("invalid login data for user: %s",
			data.Email)
	}
	u, found, err := user.FindByEmail(db, data.Email)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, notFound("cannot find user: %s", data.Email)
	}

	log.Infof("login request for user: %s", u)
	if err = user.AuthenticateUser(db, u, data.Password); err != nil {
		return nil, forbidden("invalid password for user: %s",
			data.Email)
	}
	if err = session.DeleteByUserID(db, u.ID); err != nil {
		return nil, fmt.Errorf("cannot delete user: %s: %v", u, err)
	}
	s, err := session.New(db, u)
	log.Debugf("login: new session: %s", s)
	if err != nil {
		return nil, err
	}
	putAuthCache(s)
	return s, nil
}

func getLogin(r *request) (interface{}, error) {
	log.Debugf("session: %s", r.s)
	return r.s.User, nil
}

func getLogout(r *request) (interface{}, error) {
	log.Debugf("session: %s", r.s)
	if err := session.DeleteByUserID(db, r.s.User.ID); err != nil {
		return nil, fmt.Errorf("cannot delete session: %s: %v", r.s, err)
	}
	authCache.Remove(r.s.Auth)
	return nil, nil
}

func getUser(r *request) (interface{}, error) {
	log.Debugf("get user: id: %d", r.id)
	if r.id == 0 { // list all users (root only)
		users, err := user.All(db)
		return api.Users{Users: users}, err
	}
	// list self user
	u, found, err := user.FindByID(db, r.id)
	if err != nil {
		return user.User{}, internalServerError("cannot find user-id: %d: %v",
			r.id, err)
	}
	if !found {
		return user.User{}, notFound("cannnot find user-id: %d", r.id)
	}
	return u, nil
}

func postUser(r *request) (interface{}, error) {
	data := r.d.(api.CreateUserRequest)
	err := transaction(func(db database.DB) error {
		var err error
		data.User, err = user.New(db, data.User)
		if err != nil {
			return badRequest("cannot create new user: %v", err)
		}
		if err := user.SetUserPassword(db, data.User, data.Password); err != nil {
			return badRequest("cannot set password: %v", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	log.Infof("created user: %s", data.User)
	return data.User, nil
}

func putUser(r *request) (interface{}, error) {
	data := r.d.(api.CreateUserRequest)
	err := transaction(func(db database.DB) error {
		if err := user.UpdateUser(db, data.User); err != nil {
			return err
		}
		if data.Password == "" { // do not update emtpy passwords
			return nil
		}
		if err := user.SetUserPassword(db, data.User, data.Password); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return data.User, nil
}

func deleteUser(r *request) (interface{}, error) {
	// TODO: delete all projects of the particular user
	if err := user.DeleteUserByID(db, r.id); err != nil {
		return nil, notFound("cannot delete user-id: %d: %v", r.id, err)
	}
	return nil, nil
}

func forwardGetRequest(r *request) (interface{}, error) {
	url := forwardURL(r)
	log.Debugf("forwarding request: GET %s", url)
	res, err := http.Get(url)
	if err != nil {
		return nil, internalServerError("cannot forward get request: %v", err)
	}
	defer res.Body.Close()
	if !api.IsValidJSONResponse(res, http.StatusOK) {
		return nil, errorFromCode(res.StatusCode, "bad response [%s]",
			res.Header.Get("Content-Type"))
	}
	return copyResponse(res.Body)
}

func forwardPostRequest(r *request) (interface{}, error) {
	url := forwardURL(r)
	log.Debugf("forwarding request: POST %s", url)
	res, err := http.Post(url, r.r.Header.Get("Content-Type"), r.r.Body)
	if err != nil {
		return nil, internalServerError("cannot forward post request: %v", err)
	}
	defer res.Body.Close()
	if !api.IsValidJSONResponse(res, http.StatusOK, http.StatusCreated) {
		return nil, errorFromCode(res.StatusCode, "bad response [%s]",
			res.Header.Get("Content-Type"))
	}
	return copyResponse(res.Body)
}

func forwardDeleteRequest(r *request) (interface{}, error) {
	url := forwardURL(r)
	log.Debugf("forwarding request: DELETE %s", url)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return nil, internalServerError("cannot forward delete request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, internalServerError("cannot forward post request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errorFromCode(res.StatusCode, "bad response from backend")
	}
	return nil, nil
}

// just handle api-version once
func getVersion(r *request) (interface{}, error) {
	if version.Version == "" {
		v, err := forwardGetRequest(r)
		if err != nil {
			return nil, internalServerError("cannot get api-version: %v", err)
		}
		if err := json.NewDecoder(bytes.NewBuffer(v.([]byte))).Decode(&version); err != nil {
			return nil, internalServerError("cannot read version: %v", err)
		}
	}
	return version, nil
}

//
// helper functions
//
func transaction(f func(db database.DB) error) error {
	tx, err := db.Begin()
	if err != nil {
		return internalServerError("transaction begin error: %v", err)
	}
	if err := f(tx); err != nil {
		if e2 := tx.Rollback(); e2 != nil {
			return internalServerError(
				"transaction rollback error: %v: %v", err, e2,
			)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return internalServerError("transaction commit error: %v", err)
	}
	return nil
}

func copyResponse(r io.Reader) (interface{}, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, internalServerError("cannot copy data: %v", err)
	}
	return data, nil
}

func forwardURL(r *request) string {
	url := r.r.URL.String()
	i := strings.LastIndex(url, "?")
	if i == -1 {
		return pocoweb + url
	}
	return pocoweb + url[0:i] + "?userid=" + strconv.Itoa(int(r.s.User.ID))
}
