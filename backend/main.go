package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net/http"
	"os"
	//"path"
	"github.com/codegangsta/negroni"
	"github.com/evalphobia/logrus_sentry"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"golang.org/x/crypto/ssh"
	"gopkg.in/boj/redistore.v1"
	"path/filepath"
	"strconv"
	"sync"
	"text/template"
	"utils"
)

const (
	PGDBHost   = "localhost"
	PGDBName   = "dittofi"
	PGDBUser   = "dittofi"
	PGDBPass   = "dittofi"
	PGDBSchema = "app_72"
)

const (
	SMTPHost     = ""
	SMTPPort     = 587
	SMTPUsername = ""
	SMTPPassword = ""
)

const (
	ProductionMode = "production"
	TestingMode    = "testing"
)

var runtimeMode string

const sentryDSN = ""

const (
	RediStoreMaxIdle = 1
	RediStoreNetwork = "tcp"
	RediStoreAddress = ":6379"

	RediStorePassword = ""

	RediStoreAuthenticationKey = "abc123"

	RediStoreEncryptionKey = ""

	LoginSessionName      = "session-key"
	SessionValueUserIDKey = "user_id"
	InternalHeaderUserID  = "ih_user_id"
)

const FileSystemRoot = "/srv/data"

var port string
var host string
var pg *sqlx.DB
var log *logrus.Logger
var loginSessions *redistore.RediStore
var templates *template.Template
var fs *FileSystem

func main() {
	flag.StringVar(&port, "port", "8000", "the port the http server listens on")
	flag.StringVar(&host, "host", "0.0.0.0", "the host the http server listens on")
	flag.StringVar(&runtimeMode, "mode", TestingMode, "'testing' disables logging to sentry, 'production' enables logging to sentry")
	flag.Parse()

	log = setUpLogger()
	pg = connectPostgres()
	templates = setupTemplates()
	loginSessions = configRediStore()
	defer loginSessions.Close()
	fs = NewFileSystem(FileSystemRoot)

	router := configRouter()

	n := negroni.New()
	n.Use(negroni.NewRecovery())
	n.UseHandler(router)
	n.Run(fmt.Sprintf("%s:%s", host, port))
}

func connectPostgres() *sqlx.DB {
	if pg != nil {
		// already connected
		return pg
	}

	log.WithFields(logrus.Fields{
		"db_host": PGDBHost,
	}).Info("Connect to PostgreSQL: ...")

	connString := fmt.Sprintf("dbname=%s user=%s password=%s host=%s sslmode=disable search_path=%s",
		PGDBName, PGDBUser, PGDBPass, PGDBHost, PGDBSchema)

	pg = sqlx.MustConnect("postgres", connString)
	pg.Exec(fmt.Sprintf("set search_path='%s'", PGDBSchema))
	pg.SetMaxIdleConns(1)
	pg.SetMaxOpenConns(32)
	log.Info("... Connected to PostgreSQL")

	return pg
}

func setupTemplates() *template.Template {
	var err error
	templates, err = template.ParseGlob("templates/*.tmp")
	if err != nil {
		log.Println(err)
	}

	return templates
}

func setUpLogger() *logrus.Logger {
	log := logrus.New()

	// log to Sentry
	if runtimeMode == ProductionMode {
		hook, err := logrus_sentry.NewSentryHook(sentryDSN, []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		})

		if err != nil {
			log.Fatal(err)
		} else {
			hook.StacktraceConfiguration.Enable = true
			hook.StacktraceConfiguration.Skip = 0
			hook.StacktraceConfiguration.Context = 2
			log.Hooks.Add(hook)
		}
	}

	// log to system
	hook, err := logrus_syslog.NewSyslogHook("udp", "localhost:514", syslog.LOG_INFO, "")
	if err != nil {
		log.Fatal(err)
	} else {
		log.AddHook(hook)
	}

	return log
}

func configRediStore() *redistore.RediStore {
	var keyPairs [][]byte
	if len(RediStoreAuthenticationKey) < 1 {
		panic("no authentication key set for RediStore")
	} else {
		keyPairs = append(keyPairs, []byte(RediStoreAuthenticationKey))
	}

	if l := len(RediStoreEncryptionKey); l > 0 {
		if l == 16 || l == 24 || l == 32 {
			keyPairs = append(keyPairs, []byte(RediStoreEncryptionKey))
		} else {
			panic("wrong length for encryption key set for RediStore")
		}
	}

	store, err := redistore.NewRediStore(RediStoreMaxIdle, RediStoreNetwork, RediStoreAddress, RediStorePassword, keyPairs...)
	if err != nil {
		panic(err)
	}

	return store
}

func addLoginSession(w *http.ResponseWriter, r *http.Request, userID int) (err error) {
	// Get a session.
	var loginSession *sessions.Session
	loginSession, err = loginSessions.Get(r, LoginSessionName)
	if err != nil {
		return
	}

	// Add a value.
	loginSession.Values[SessionValueUserIDKey] = userID

	// Save.
	err = sessions.Save(r, *w)

	return
}

func removeLoginSession(w *http.ResponseWriter, r *http.Request) (err error) {
	// Get the session.
	var loginSession *sessions.Session
	loginSession, err = loginSessions.Get(r, LoginSessionName)
	if err != nil {
		return
	}

	// Delete session.
	loginSession.Options.MaxAge = -1

	// Save.
	err = sessions.Save(r, *w)

	return
}

func getLoginSessionUserID(r *http.Request) (userID int, err error) {
	// attempt to see if internal header set already otherwise attempt to find
	var userIDStr = r.Header.Get(InternalHeaderUserID)
	if len(userIDStr) == 0 {
		// Get a session.

		var loginSession *sessions.Session
		loginSession, err = loginSessions.Get(r, LoginSessionName)
		if err != nil {
			return
		}

		if iUserID, ok := loginSession.Values[SessionValueUserIDKey]; !ok {
			err = fmt.Errorf("no user id found")
			return
		} else if userID, ok = iUserID.(int); !ok {
			err = fmt.Errorf("unexpected user id type not int")
			return
		}
	} else {
		userID, err = strconv.Atoi(userIDStr)
	}

	return
}

func RequireLogin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := getLoginSessionUserID(r)
		if err != nil {
			utils.JSON(w, http.StatusUnauthorized, utils.Response{nil, "login required", utils.ErrCodeUnAuthorized})
			return
		}

		r.Header.Set(InternalHeaderUserID, fmt.Sprint(userID))
		handler(w, r)
	}
}

type FileSystem struct {
	// control concurrent access to FileLocks
	sync.Mutex
	// control concurrent read/write access to files
	// TODO may want to add some mechanism to clean up FileLocks occasionally
	FileLocks map[string]*sync.RWMutex
	Root      string
	// TODO may want to add mechanism to clean up temporary directory upon exiting server
	TempDir string
}

func (fs *FileSystem) GetFileLock(path string) (lock *sync.RWMutex) {
	fs.Lock()
	defer fs.Unlock()
	lock, ok := fs.FileLocks[path]
	if !ok {
		lock = &sync.RWMutex{}
		fs.FileLocks[path] = lock
	}

	return
}

func (fs *FileSystem) GetFile(path string, flag int) (f File, err error) {
	lock := fs.GetFileLock(path)
	lock.RLock()
	defer lock.RUnlock()

	// generate full path for final store location
	var fullPath = path
	if len(fs.Root) > 0 {
		fullPath = filepath.Join(fs.Root, path)
	}

	// Open file.
	var srcFile *os.File
	srcFile, err = os.OpenFile(fullPath, flag, 0755)
	if err != nil {
		return
	} else {
		f.File = srcFile
	}

	f.FilePath = path

	return
}

func (fs *FileSystem) SetFile(f File, path string, overwrite bool) (err error) {
	lock := fs.GetFileLock(path)
	lock.Lock()
	defer lock.Unlock()

	// generate full path for final store location
	var fullPath = path
	if len(fs.Root) > 0 {
		fullPath = filepath.Join(fs.Root, path)
	}

	// create any missing directories
	err = os.MkdirAll(filepath.Dir(fullPath), 0755)
	if err != nil {
		return
	}

	// set file flags to allow overwriting existing file
	var fileFlag = os.O_WRONLY | os.O_CREATE
	if overwrite {
		fileFlag |= os.O_TRUNC
	} else {
		fileFlag |= os.O_EXCL
	}

	// open/create file
	var file *os.File
	file, err = os.OpenFile(fullPath, fileFlag, 0666)
	if !overwrite && os.IsExist(err) {
		err = fmt.Errorf(`cannot overwrite existing file "%s"`, path)
		return
	} else if err != nil {
		return
	}
	defer file.Close()

	// copy date in temporary file to new file
	if f.File != nil {
		_, err = f.File.Seek(0, 0)
		if err != nil {
			return
		}

		_, err = io.Copy(file, f.File)
		if err != nil {
			return
		}
	}

	return
}

func (fs *FileSystem) SetTempFile(data io.Reader) (f File, err error) {
	var filePrefix string
	if data == nil {
		filePrefix = "copy"
	} else {
		filePrefix = "upload"
	}

	// create temporary file
	var osFile *os.File
	osFile, err = ioutil.TempFile(fs.TempDir, fmt.Sprintf("%s-*", filePrefix))
	if err != nil {
		return
	}

	// copy data if available
	if data != nil {
		_, err = io.Copy(osFile, data)
		if err != nil {
			return
		}

		// reset seek to beginning of file
		_, err = osFile.Seek(0, 0)
		if err != nil {
			return
		}
	}

	f.File = osFile

	return
}

func NewFileSystem(root string) (fs *FileSystem) {
	if len(root) == 0 || root == "/" {
		log.Fatalf(`invalid file system root "%s" set`, root)
	}

	tempDir, err := ioutil.TempDir("", "temp-file-dir*")
	if err != nil {
		log.Fatal(err)
	}

	fs = &FileSystem{
		Mutex:     sync.Mutex{},
		FileLocks: make(map[string]*sync.RWMutex, 0),
		Root:      root,
		TempDir:   tempDir,
	}

	return
}

func PublicKey(path string) (*ssh.AuthMethod, error) {
	/*key, err := ioutil.ReadFile(path)
	  if err != nil {
	          return nil, err
	  }*/

	signer, err := ssh.ParsePrivateKey([]byte(path))
	if err != nil {
		return nil, err
	}

	authMethod := ssh.PublicKeys(signer)
	return &authMethod, nil
}
