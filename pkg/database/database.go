package database

import (
	"database/sql"
	"fmt"
	"samoscout/pkg/config"
	"time"

	_ "github.com/lib/pq"
)

var DebugLog func(string, ...interface{})

type DB struct {
	conn    *sql.DB
	enabled bool
}

type SubdomainRecord struct {
	Domain     string
	Subdomain  string
	Status     string
	FirstSeen  time.Time
	LastSeen   time.Time
}

const DBName = "samoscout_track"

func New(cfg *config.Database) (*DB, error) {
	db := &DB{
		enabled: cfg.Enabled,
	}

	if !cfg.Enabled {
		fmt.Println("[INF] Database connection disabled.")
		return db, nil
	}

	postgresConnStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password)

	postgresConn, err := sql.Open("postgres", postgresConnStr)
	if err != nil {
		fmt.Println("[INF] Database connection disabled.")
		return db, fmt.Errorf("failed to connect to postgres: %w", err)
	}
	defer postgresConn.Close()

	if err := postgresConn.Ping(); err != nil {
		fmt.Println("[INF] Database connection disabled.")
		return db, fmt.Errorf("failed to ping postgres: %w", err)
	}

	var exists bool
	err = postgresConn.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", DBName).Scan(&exists)
	if err != nil {
		fmt.Println("[INF] Database connection disabled.")
		return db, fmt.Errorf("failed to check database existence: %w", err)
	}

	if !exists {
		_, err = postgresConn.Exec(fmt.Sprintf("CREATE DATABASE %s", DBName))
		if err != nil {
			fmt.Println("[INF] Database connection disabled.")
			return db, fmt.Errorf("failed to create database: %w", err)
		}
		fmt.Printf("[INF] Database '%s' created successfully.\n", DBName)
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, DBName)

	conn, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println("[INF] Database connection disabled.")
		return db, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := conn.Ping(); err != nil {
		conn.Close()
		fmt.Println("[INF] Database connection disabled.")
		return db, fmt.Errorf("failed to ping database: %w", err)
	}

	db.conn = conn
	fmt.Println("[INF] Database connection active.")

	if err := db.initSchema(); err != nil {
		return db, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

func (db *DB) initSchema() error {
	if !db.enabled || db.conn == nil {
		return nil
	}

	schema := `
	CREATE TABLE IF NOT EXISTS subdomains (
		id SERIAL PRIMARY KEY,
		domain VARCHAR(255) NOT NULL,
		subdomain VARCHAR(255) NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'NEW',
		first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
		UNIQUE(domain, subdomain)
	);

	CREATE INDEX IF NOT EXISTS idx_domain ON subdomains(domain);
	CREATE INDEX IF NOT EXISTS idx_status ON subdomains(status);
	CREATE INDEX IF NOT EXISTS idx_subdomain ON subdomains(subdomain);
	`

	_, err := db.conn.Exec(schema)
	return err
}

func (db *DB) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

func (db *DB) IsEnabled() bool {
	return db.enabled && db.conn != nil
}

func (db *DB) TrackSubdomains(domain string, subdomains []string) error {
	if !db.IsEnabled() {
		return nil
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	currentSubdomains := make(map[string]bool)
	for _, subdomain := range subdomains {
		currentSubdomains[subdomain] = true
	}

	for subdomain := range currentSubdomains {
		var exists bool
		err := tx.QueryRow(`
			SELECT EXISTS(SELECT 1 FROM subdomains WHERE domain = $1 AND subdomain = $2)
		`, domain, subdomain).Scan(&exists)
		if err != nil {
			return err
		}

		if exists {
			if DebugLog != nil {
				DebugLog("updating subdomain %s to ACTIVE in database", subdomain)
			}
			_, err = tx.Exec(`
				UPDATE subdomains 
				SET status = 'ACTIVE', last_seen = NOW()
				WHERE domain = $1 AND subdomain = $2
			`, domain, subdomain)
		} else {
			if DebugLog != nil {
				DebugLog("inserting new subdomain %s with status NEW into database", subdomain)
			}
			_, err = tx.Exec(`
				INSERT INTO subdomains (domain, subdomain, status, first_seen, last_seen)
				VALUES ($1, $2, 'NEW', NOW(), NOW())
			`, domain, subdomain)
		}

		if err != nil {
			return err
		}
	}

	rows, err := tx.Query(`
		SELECT subdomain FROM subdomains 
		WHERE domain = $1 AND status != 'DEAD'
	`, domain)
	if err != nil {
		return err
	}
	defer rows.Close()

	var deadSubdomains []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			return err
		}
		if !currentSubdomains[subdomain] {
			deadSubdomains = append(deadSubdomains, subdomain)
		}
	}

	for _, subdomain := range deadSubdomains {
		if DebugLog != nil {
			DebugLog("marking subdomain %s as DEAD in database (not found in current scan)", subdomain)
		}
		_, err = tx.Exec(`
			UPDATE subdomains 
			SET status = 'DEAD', last_seen = NOW()
			WHERE domain = $1 AND subdomain = $2
		`, domain, subdomain)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *DB) QuerySubdomains(domain string, status string) ([]SubdomainRecord, error) {
	if !db.IsEnabled() {
		return nil, fmt.Errorf("database is not enabled")
	}

	query := `
		SELECT domain, subdomain, status, first_seen, last_seen
		FROM subdomains
		WHERE domain = $1
	`
	args := []interface{}{domain}

	if status != "" {
		query += " AND status = $2"
		args = append(args, status)
	}

	query += " ORDER BY first_seen DESC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []SubdomainRecord
	for rows.Next() {
		var r SubdomainRecord
		if err := rows.Scan(&r.Domain, &r.Subdomain, &r.Status, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, nil
}

func (db *DB) QueryAllSubdomains(status string) ([]SubdomainRecord, error) {
	if !db.IsEnabled() {
		return nil, fmt.Errorf("database is not enabled")
	}

	query := `
		SELECT domain, subdomain, status, first_seen, last_seen
		FROM subdomains
	`
	var args []interface{}

	if status != "" {
		query += " WHERE status = $1"
		args = append(args, status)
	}

	query += " ORDER BY domain, first_seen DESC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []SubdomainRecord
	for rows.Next() {
		var r SubdomainRecord
		if err := rows.Scan(&r.Domain, &r.Subdomain, &r.Status, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, nil
}

