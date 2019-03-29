package main

import (
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/finkf/pcwgo/api"
	"github.com/finkf/pcwgo/db"
	log "github.com/sirupsen/logrus"
)

var authCache = gcache.New(20).LRU().LoaderExpireFunc(loadSessionAuthToken).Build()

func putAuthCache(s api.Session) error {
	return authCache.SetWithExpire(s.Auth, s, time.Until(time.Unix(s.Expires, 0)))
}

func getAuthCache(token string) (api.Session, error) {
	val, err := authCache.Get(token)
	if err != nil {
		return api.Session{}, err
	}
	log.Debugf("found auth-token: %s", token)
	return val.(api.Session), nil
}

func purgeAuthCache() {
	log.Debugf("purging auth cache")
	authCache.Purge()
}

func loadSessionAuthToken(token interface{}) (interface{}, *time.Duration, error) {
	str := token.(string)
	log.Debugf("[not cached] looking up auth-token: %s", str)
	s, found, err := db.FindSessionByID(database, str)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, forbidden("cannot find auth-token: %s", str)
	}
	expire := time.Until(time.Unix(s.Expires, 0))
	return s, &expire, nil
}

var projectCache = gcache.New(20).LoaderFunc(loadProjectData).Build()

func putProjectCache(p db.Project) error {
	return projectCache.Set(p.ID, p)
}

func purgeProjectCache() {
	log.Debugf("purging project cache")
	projectCache.Purge()
}

func getProjectCache(id int64) (db.Project, error) {
	val, err := projectCache.Get(id)
	if err != nil {
		return db.Project{}, err
	}
	log.Debugf("found project-id: %d", id)
	return val.(db.Project), nil
}

func loadProjectData(key interface{}) (interface{}, error) {
	id := key.(int64)
	log.Debugf("[not cached] looking up project-id: %d", id)
	p, found, err := db.FindProjectByID(database, id)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, notFound("cannot find project-id: %d", id)
	}
	return p, nil
}

var apiCache = gcache.New(20).LRU().Build()

func getAPICache(r *request, f apifunc) (interface{}, error) {
	url := r.r.URL.String()
	log.Debugf("checking cache for %s", url)
	val, err := apiCache.Get(url)
	if err != nil && err != gcache.KeyNotFoundError {
		return nil, err
	}
	// not cached fetch and put into cache
	if err == gcache.KeyNotFoundError {
		log.Debugf("not cached: %s", url)
		val, err = f(r)
		if err != nil {
			return nil, err
		}
		log.Debugf("caching %s", url)
		return val, apiCache.Set(url, val)
	}
	log.Infof("%s cached", url)
	return val, nil
}

func purgeAPICache(r *request) {
	url := r.r.URL.String()
	for _, key := range apiCache.Keys() {
		if strings.HasPrefix(key.(string), url) {
			log.Debugf("purging api cache url: %s", key.(string))
			apiCache.Remove(key)
		}
	}
}
