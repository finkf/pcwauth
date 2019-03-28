module github.com/finkf/pcwauth

require (
	github.com/bluele/gcache v0.0.0-20171010155617-472614239ac7
	github.com/finkf/pcwgo/api v0.3.0
	github.com/finkf/pcwgo/db v0.2.0
	github.com/go-sql-driver/mysql v1.4.0
	github.com/sirupsen/logrus v1.4.0
	google.golang.org/appengine v1.3.0 // indirect
)

replace github.com/finkf/pcwgo/api v0.2.0 => ../pcwgo/api
