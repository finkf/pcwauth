package main // import "github.com/finkf/pcwauth"

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/finkf/pcwgo/api"
	"github.com/finkf/pcwgo/db"
	"github.com/finkf/pcwgo/service"
	log "github.com/sirupsen/logrus"
)

var (
	listen         string
	cert           string
	key            string
	dsn            string
	pocoweb        string
	profiler       string
	users          string
	postcorrection string
	ocr            string
	debug          bool
	version        api.Version
	vonce          sync.Once
	client         *http.Client
)

func init() {
	flag.StringVar(&listen, "listen", ":8080", "set listening host")
	flag.StringVar(&cert, "cert", "", "set cert file (no tls if omitted)")
	flag.StringVar(&key, "key", "", "set key file (no tls if omitted)")
	flag.StringVar(&dsn, "dsn", "",
		"set mysql connection DSN (user:pass@proto(host)/dbname)")
	flag.StringVar(&pocoweb, "pocoweb", "", "set host of pocoweb")
	flag.StringVar(&profiler, "profiler", "", "set host of pcwprofiler")
	flag.StringVar(&users, "users", "", "set host of pcwusers")
	flag.StringVar(&postcorrection, "postcorrection", "",
		"set host of pcwpostcorrection")
	flag.StringVar(&ocr, "ocr", "", "set host of pcwocr")
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
	// jobs
	http.HandleFunc("/jobs/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithIDs(service.WithAuth(getJob()), "jobs"))))
	// ocr
	http.HandleFunc("/ocr/", service.WithLog(service.WithMethods(
		http.MethodGet, service.WithAuth(forward(ocr)))))
	http.HandleFunc("/ocr/predict/", service.WithLog(service.WithMethods(
		http.MethodPost, service.WithAuth(
			service.WithProject(projectOwner(forward(ocr)))),
		http.MethodGet, service.WithAuth(
			service.WithProject(projectOwner(forward(ocr)))))))
	http.HandleFunc("/ocr/train/", service.WithLog(service.WithMethods(
		http.MethodPost, service.WithAuth(
			service.WithProject(projectOwner(forward(ocr)))))))
	// postcorrection
	http.HandleFunc("/postcorrect/el/books/", service.WithLog(service.WithMethods(
		http.MethodPost, service.WithAuth(
			service.WithProject(projectOwner(forward(postcorrection)))),
		http.MethodGet, service.WithAuth(
			service.WithProject(projectOwner(forward(postcorrection)))))))
	http.HandleFunc("/postcorrect/rrdm/books/", service.WithLog(service.WithMethods(
		http.MethodPost, service.WithAuth(
			service.WithProject(projectOwner(forward(postcorrection)))),
		http.MethodGet, service.WithAuth(
			service.WithProject(projectOwner(forward(postcorrection)))))))
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
	re := regexp.MustCompile(`/users/(\d+)`)
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		log.Debugf("rootOrSelf: %s", d.Session.User)
		var uid int
		if n := service.ParseIDs(r.URL.String(), re, &uid); n == 0 {
			service.ErrorResponse(w, http.StatusNotFound,
				"cannot find: %s", r.URL.String())
			return
		}
		log.Debugf("user id: %d", uid)
		if !d.Session.User.Admin && int64(uid) != d.Session.User.ID {
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

func getJob() service.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, d *service.Data) {
		jobID := d.IDs["jobs"]
		status, err := findJob(jobID)
		// return not running job if the job does not exist
		// to indicate that it is ok to run a job
		if err == errJobNotFound {
			service.JSONResponse(w, api.JobStatus{
				JobID:      jobID,
				BookID:     jobID,
				StatusID:   db.StatusIDEmpty,
				StatusName: db.StatusEmpty,
			})
			return
		}
		if err != nil {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"cannot get job status: %v", err)
			return
		}
		// failed job returns 500 so caller just needs to handle
		// http return codes
		if status.StatusID == db.StatusIDFailed {
			service.ErrorResponse(w, http.StatusInternalServerError,
				"job %s failed", status.JobName)
			return
		}
		service.JSONResponse(w, status)
	}
}

var errJobNotFound = errors.New("job not found")

func findJob(jobID int) (*api.JobStatus, error) {
	// search for the project id mapped to the job/book-ID
	// (project.origin is joined with jobid in the view)
	stmt := `select * from job_status_project_view where projectid=?`
	rows, err := db.Query(service.Pool(), stmt, jobID)
	if err != nil {
		return nil, fmt.Errorf("cannot query job id %d: %v", jobID, err)
	}
	if !rows.Next() {
		return nil, errJobNotFound
	}
	var sid, jid, pid int
	var ts int64
	var jname, sname string
	if err := rows.Scan(&jid, &sid, &jname, &ts, &sname, &pid); err != nil {
		return nil, fmt.Errorf("cannot scan job id %d: %v", jobID, err)
	}
	return &api.JobStatus{
		JobID:      jid,
		BookID:     jid, // always equal to the bookID
		StatusID:   sid,
		StatusName: sname,
		JobName:    jname,
		Timestamp:  ts,
		// TODO: ProjectID:  pid,
	}, nil
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
		case http.MethodPut:
			req, err := http.NewRequest(http.MethodPut, url, r.Body)
			if err != nil {
				service.ErrorResponse(w, http.StatusInternalServerError,
					"cannot forward: %v", err)
				return
			}
			res, err := client.Do(req)
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
