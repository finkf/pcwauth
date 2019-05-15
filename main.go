package main // import "github.com/finkf/pcwauth"

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/finkf/pcwgo/api"
	"github.com/finkf/pcwgo/db"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
)

var (
	database *sql.DB
	host     string
	cert     string
	key      string
	dbdsn    string
	pocoweb  string
	profiler string
	rName    string
	rPass    string
	rEmail   string
	rInst    string
	debug    bool
	version  api.Version
	client   *http.Client
)

func init() {
	flag.StringVar(&host, "listen", ":8080", "set listening host")
	flag.StringVar(&cert, "cert", "", "set cert file (no tls if omitted)")
	flag.StringVar(&key, "key", "", "set key file (no tls if omitted)")
	flag.StringVar(&dbdsn, "db", "", "set mysql connection DSN (user:pass@proto(host)/dbname)")
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
		log.Errorf("error: %v", err)
		os.Exit(1)
	}
}

func setupDatabase() error {
	var err error
	log.Debugf("connecting to db using: %s", dbdsn)
	database, err = sql.Open("mysql", dbdsn)
	if err != nil {
		return fmt.Errorf("cannot connect to database: %v", err)
	}
	if err = database.Ping(); err != nil {
		return fmt.Errorf("cannot ping database: %v", err)
	}
	database.SetMaxOpenConns(100)
	database.SetConnMaxLifetime(100)
	database.SetMaxIdleConns(10)

	if rPass == "" || rEmail == "" || rName == "" {
		return nil
	}
	return insertUser()
}

func insertUser() error {
	root := api.User{
		Name:      rName,
		Email:     rEmail,
		Institute: rInst,
		Admin:     true,
	}
	_, found, err := db.FindUserByEmail(database, root.Email)
	if err != nil {
		return fmt.Errorf("cannot find user %s: %v", root, err)
	}
	if found { // root allready exists
		return nil
	}
	if err = db.InsertUser(database, &root); err != nil {
		return fmt.Errorf("cannot create user %s: %v", root, err)
	}
	if err := db.SetUserPassword(database, root, rPass); err != nil {
		return fmt.Errorf("cannot set password for %s: %v", root, err)
	}
	return nil
}

func main() {
	flag.Parse()
	if debug {
		log.SetLevel(log.DebugLevel)
	}
	must(setupDatabase())
	defer database.Close()
	// login
	http.HandleFunc(api.LoginURL, logURL(apih(apiGetPost(
		withAuth(getLogin),
		postLogin))))
	http.HandleFunc(api.LogoutURL, logURL(apih(apiGetPost(
		withAuth(getLogout),
		postLogin))))
	// user management
	http.HandleFunc("/users", logURL(apih(withAuth(onlyRoot(
		apiGetPost(
			getUser,
			withUser(postUser)))))))
	http.HandleFunc("/users/", logURL(apih(withAuth(withUserID(rootOrSelf(
		apiGetPutDelete(
			getUser,
			withUser(putUser),
			deleteUser)))))))
	// book management
	http.HandleFunc("/books", logURL(apih(withAuth( /*cached(*/
		apiGetPost(
			forwardGetRequest(pocoweb),
			onlyRoot(forwardPostRequest(pocoweb))))))) /*)*/
	http.HandleFunc("/books/", logURL(apih(withAuth( /*cached(*/
		withProject(onlyProjectOwner(
			apiGetPostDelete(
				forwardGetRequest(pocoweb),
				forwardPostRequest(pocoweb),
				forwardDeleteRequest(pocoweb)))))))) /*)*/
	// profiling
	http.HandleFunc("/profile/",
		logURL(apih(apiGet(withProject(onlyProjectOwner(forwardGetRequest(profiler)))))))
	// misc
	http.HandleFunc(api.VersionURL, apih(apiGet(getVersion)))
	http.HandleFunc("/profiler-languages", logURL(apih( /*cached(*/
		apiGet(forwardGetRequest(pocoweb))))) /*)*/

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
		if r, ok := res.(io.ReadCloser); ok {
			defer r.Close()
			apiForward(w, r)
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

func apiForward(w http.ResponseWriter, r io.Reader) {
	if r == nil {
		return
	}
	// reader must contain JSON encoded data
	w.Header()["Content-Type"] = []string{"application/json"}
	n, err := io.Copy(w, r)
	if err != nil {
		log.Errorf("could not forward: %v", err)
	}
	log.Infof("forwarded %d bytes", n)
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

func withAuth(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		if len(r.r.URL.Query()["auth"]) != 1 {
			return nil, forbidden("missing auth parameter")
		}
		auth := r.r.URL.Query()["auth"][0]
		val, err := authCache.Get(auth)
		if err != nil {
			return nil, err
		}
		r.s = val.(api.Session)
		log.Infof("user %s authenticated: %s (expires: %s)",
			r.s.User, r.s.Auth, time.Unix(r.s.Expires, 0).Format(time.RFC3339))
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

var restProjectIDRegex = regexp.MustCompile(`/books/(\d+)`)

func withProject(f apifunc) apifunc {
	return func(r *request) (interface{}, error) {
		url := r.r.URL.String()
		log.Debugf("matching url: %s", url)
		m := restProjectIDRegex.FindStringSubmatch(url)
		if m == nil || len(m) != 2 {
			return nil, notFound("no such url: %s [%v]", url, m)
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
		log.Debugf("with user-data: %s", data.User)
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
	user, found, err := db.FindUserByEmail(database, data.Email)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, notFound("cannot find user: %s", data.Email)
	}

	log.Infof("login request for user: %s", user)
	if err = db.AuthenticateUser(database, user, data.Password); err != nil {
		return nil, forbidden("invalid password for user: %s: %v", data.Email, err)
	}
	if err = db.DeleteSessionByUserID(database, user.ID); err != nil {
		return nil, fmt.Errorf("cannot delete user: %s: %v", user, err)
	}

	s, err := db.InsertSession(database, user)
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
	authCache.Remove(r.s.Auth)
	if err := db.DeleteSessionByUserID(database, r.s.User.ID); err != nil {
		return nil, fmt.Errorf("cannot delete session: %s: %v", r.s, err)
	}
	return nil, nil
}

func getUser(r *request) (interface{}, error) {
	if r.id == 0 { // list all users (root only)
		log.Debugf("get all users")
		users, err := db.FindAllUsers(database)
		return api.Users{Users: users}, err
	}
	// list self user
	u, found, err := db.FindUserByID(database, r.id)
	if err != nil {
		return api.User{}, internalServerError("cannot find user-id: %d: %v",
			r.id, err)
	}
	if !found {
		return api.User{}, notFound("cannnot find user-id: %d", r.id)
	}
	log.Printf("get user: %s", u)
	return u, nil
}

func postUser(r *request) (interface{}, error) {
	// this must not fail
	data := r.d.(api.CreateUserRequest)
	t := db.NewTransaction(database.Begin())
	t.Do(func(database db.DB) error {
		if err := db.InsertUser(database, &data.User); err != nil {
			return badRequest("cannot create new user: %v", err)
		}
		return nil
	})
	t.Do(func(database db.DB) error {
		if err := db.SetUserPassword(database, data.User, data.Password); err != nil {
			return badRequest("cannot set password: %v", err)
		}
		return nil
	})
	return data.User, t.Done()
}

func putUser(r *request) (interface{}, error) {
	// this must not fail
	data := r.d.(api.CreateUserRequest)
	t := db.NewTransaction(database.Begin())
	t.Do(func(database db.DB) error {
		if err := db.UpdateUser(database, data.User); err != nil {
			return err
		}
		return nil
	})
	t.Do(func(database db.DB) error {
		if data.Password == "" { // do not update emtpy passwords
			return nil
		}
		if err := db.SetUserPassword(database, data.User, data.Password); err != nil {
			return err
		}
		return nil
	})
	if err := t.Done(); err != nil {
		return nil, err
	}
	r.s.User = data.User
	putAuthCache(r.s)
	return r.s.User, nil
}

func deleteUser(r *request) (interface{}, error) {
	// TODO: delete all projects of the particular user
	if err := db.DeleteUserByID(database, r.id); err != nil {
		return nil, notFound("cannot delete user-id: %d: %v", r.id, err)
	}
	return nil, nil
}

func drain(res *http.Response) {
	defer res.Body.Close()
	io.Copy(ioutil.Discard, res.Body)
}

func forwardGetRequest(base string) func(r *request) (interface{}, error) {
	return func(r *request) (interface{}, error) {
		url := r.forwardURL(base)
		log.Debugf("forwarding request: GET %s", url)
		res, err := client.Get(url)
		if err != nil {
			return nil, internalServerError("cannot forward get request: %v", err)
		}
		log.Debugf("got answer from forward request")
		if !api.IsValidJSONResponse(res, http.StatusOK) {
			drain(res)
			return nil, errorFromCode(res.StatusCode, "bad response [%s]",
				res.Header.Get("Content-Type"))
		}
		return res.Body, nil
	}
}

func forwardPostRequest(base string) func(r *request) (interface{}, error) {
	return func(r *request) (interface{}, error) {
		url := r.forwardURL(base)
		log.Infof("forwarding request: POST %s", url)
		res, err := client.Post(url, r.r.Header.Get("Content-Type"), r.r.Body)
		if err != nil {
			return nil, internalServerError("cannot forward post request: %v", err)
		}
		log.Debugf("got answer from forward request")
		if !api.IsValidJSONResponse(res, http.StatusOK, http.StatusCreated) {
			drain(res)
			return nil, errorFromCode(res.StatusCode, "bad response [%s]",
				res.Header.Get("Content-Type"))
		}
		return res.Body, nil
	}
}

func forwardDeleteRequest(base string) func(r *request) (interface{}, error) {
	return func(r *request) (interface{}, error) {
		url := r.forwardURL(base)
		log.Debugf("forwarding request: DELETE %s", url)
		req, err := http.NewRequest(http.MethodDelete, url, nil)
		if err != nil {
			return nil, internalServerError("cannot forward delete request: %v", err)
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, internalServerError("cannot forward post request: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			drain(res)
			return nil, errorFromCode(res.StatusCode, "bad response from backend")
		}
		return nil, nil
	}
}

// just handle api-version once
func getVersion(r *request) (interface{}, error) {
	if version.Version == "" {
		v, err := forwardGetRequest(pocoweb)(r)
		if err != nil {
			return nil, internalServerError("cannot get api-version: %v", err)
		}
		body := v.(io.ReadCloser)
		defer body.Close()
		if err := json.NewDecoder(body).Decode(&version); err != nil {
			return nil, internalServerError("cannot read version: %v", err)
		}
		body.Close()
	}
	return version, nil
}

func (r *request) forwardURL(base string) string {
	url := r.r.URL.String()
	i := strings.LastIndex(url, "?")
	if i == -1 {
		return fmt.Sprintf("%s%s?userid=%d", base, url, r.s.User.ID)
	}
	return fmt.Sprintf("%s%s&userid=%d", base, url, r.s.User.ID)
}
