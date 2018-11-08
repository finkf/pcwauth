module github.com/finkf/pcwauth

require (
	github.com/bluele/gcache v0.0.0-20171010155617-472614239ac7
	github.com/go-sql-driver/mysql v1.4.0
	github.com/sirupsen/logrus v1.2.0
	github.com/finkf/pcwgo/api v0.0.0
	github.com/finkf/pcwgo/database/project v0.0.0
	github.com/finkf/pcwgo/database/user v0.0.0
	github.com/finkf/pcwgo/database/session v0.0.0
	github.com/finkf/pcwproxy/database/sqlite v0.0.0
	github.com/finkf/pcwproxy/database v0.0.0
)

replace (
	github.com/finkf/pcwgo/api => ../pcwgo/api
	github.com/finkf/pcwgo/database/project => ../pcwgo/database/project
	github.com/finkf/pcwgo/database/user => ../pcwgo/database/user
	github.com/finkf/pcwgo/database/session => ../pcwgo/database/session
	github.com/finkf/pcwgo/database => ../pcwgo/database/
	github.com/finkf/pcwgo/database/sqlite => ../pcwgo/database/sqlite
)
