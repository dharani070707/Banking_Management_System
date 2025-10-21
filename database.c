// database.c
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h> 
#include <errno.h>

#define DB_PATH "bank.db"

sqlite3 *db = NULL;
int db_fd = -1; 

int db_execute_protected(const char *sql) {
    int rc;
    char *err_msg = 0;
    
    if (flock(db_fd, LOCK_EX | LOCK_NB) == -1) {
        if (errno == EWOULDBLOCK) {
            fprintf(stderr, "DB Locked: Concurrent operation in progress. Try again.\n");
            return -2; 
        }
        perror("Error acquiring exclusive file lock (flock)");
        return -1;
    }

    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);

    if (flock(db_fd, LOCK_UN) == -1) {
        perror("Error releasing exclusive file lock (flock)");
    }
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0; // Success
}

int db_init() {
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    db_fd = open(DB_PATH, O_RDWR | O_CREAT, 0666);
    if (db_fd < 0) {
        perror("Error opening DB file for locking");
        sqlite3_close(db);
        return -1;
    }

    char *err_msg = 0;
    const char *sql_create = 
        "CREATE TABLE IF NOT EXISTS Users("
            "user_id INTEGER PRIMARY KEY, "
            "username TEXT UNIQUE, "
            "password TEXT, "
            "role_id INT, " // 1=Customer, 2=Employee, 3=Manager, 4=Admin
            "is_active INT DEFAULT 1,"
	    "is_logged_in INT DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS Accounts("
            "account_id INTEGER PRIMARY KEY, "
            "user_id INT UNIQUE, "
            "balance REAL NOT NULL);"
        "CREATE TABLE IF NOT EXISTS Transactions("
            "txn_id INTEGER PRIMARY KEY, "
            "account_id INT, "
            "type TEXT, " // DEPOSIT, WITHDRAW, TRANSFER, FEE, LOAN_DISBURSE
            "amount REAL, "
            "details TEXT, "
            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS Loans("
            "loan_id INTEGER PRIMARY KEY, "
            "account_id INT, "
            "amount REAL, "
            "status TEXT DEFAULT 'PENDING', "
            "assigned_employee_id INT);"
	"CREATE TABLE IF NOT EXISTS Feedback("
            "feedback_id INTEGER PRIMARY KEY, "
            "user_id INT, "
            "message TEXT, "
            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);"
        "INSERT OR IGNORE INTO Users (user_id, username, password, role_id) VALUES "
            "(101, 'cust1', 'pass', 1), (102,'cust2','pass2',1), (201, 'emp1', 'pass', 2), (301, 'mgr1', 'pass', 3), (401, 'admin1', 'pass', 4);"
        "INSERT OR IGNORE INTO Accounts (account_id, user_id, balance) VALUES "
            "(10001, 101, 5000.00),(10002,102,200);"
        ;

    if (sqlite3_exec(db, sql_create, NULL, NULL, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    printf("DB: Tables checked/created and sample users loaded.\n");
    return 0;
}

void db_close() {
    if (db) sqlite3_close(db);
    if (db_fd >= 0) close(db_fd);
}
