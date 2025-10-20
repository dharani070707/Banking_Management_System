#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <sqlite3.h> 
#include "database.c" 

#define PORT 8080
#define BACKLOG 10
#define BUFFER_SIZE 2048
#define MAX_TOKENS 10

// --- Utility Structures and Functions ---
void sigchld_handler(int s) {
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

typedef struct {
    int user_id;
    int role_id;
    double balance;
    int is_active;
    char details[BUFFER_SIZE]; 
} UserData;

// SQLite Callbacks (kept for logic processing)
static int auth_callback(void *data, int argc, char **argv, char **azColName) {
    UserData *u_data = (UserData *)data;
    if (argc >= 4) {
        u_data->user_id = atoi(argv[0]); 
        u_data->role_id = atoi(argv[1]); 
        u_data->balance = atof(argv[2]); 
        u_data->is_active = atoi(argv[3]);
        return 0;
    }
    return 1;
}

static int single_amount_callback(void *data, int argc, char **argv, char **azColName) {
    // data points to a double variable
    if (argc > 0 && argv[0]) {
        *(double *)data = atof(argv[0]);
    }
    return 0;
}

static int history_callback(void *data, int argc, char **argv, char **azColName) {
    UserData *u_data = (UserData *)data;
    char entry[256];
    if (strlen(u_data->details) >= BUFFER_SIZE - 256) {
        return 1;
    }
    
    if (argc >= 5) {
        snprintf(entry, 256, "%s|%s|%.2f|%s\n", argv[4], argv[2], atof(argv[3]), argv[5]);
        strncat(u_data->details, entry, BUFFER_SIZE - strlen(u_data->details) - 1);
    }
    return 0;
}

static int feedback_callback(void *data, int argc, char **argv, char **azColName) {
    UserData *u_data = (UserData *)data;
    char entry[512];
    
    if (strlen(u_data->details) >= BUFFER_SIZE - 512) {
        return 1;
    }
    
    // Format: FEEDBACK_ID | USER_ID | MESSAGE | TIMESTAMP
    if (argc >= 4) {
        snprintf(entry, 512, "[ID:%s, User:%s] %s (Time: %s)\n", argv[0], argv[1], argv[2], argv[3]);
        strncat(u_data->details, entry, BUFFER_SIZE - strlen(u_data->details) - 1);
    }
    return 0;
}

void clear_session_lock(int user_id);
void handle_logout(char *response, int user_id) {
    // FIX: Execute the lock clear immediately
    clear_session_lock(user_id);
    strcpy(response, "SUCCESS|Session terminated.");
}

void handle_admin_action(const char *action, const char *args[], int user_id, char *response);
void handle_manager_action(const char *action, const char *args[], int user_id, char *response);
void handle_employee_action(const char *action, const char *args[], int user_id, char *response);

int get_account_info(int user_id, UserData *u_data) {
    char sql[BUFFER_SIZE];
    char *err_msg = 0;
    u_data->balance = -1.0; 
    
    snprintf(sql, BUFFER_SIZE, 
        "SELECT U.user_id, U.role_id, IFNULL(A.balance, 0), U.is_active FROM Users U "
        "LEFT JOIN Accounts A ON U.user_id = A.user_id WHERE U.user_id=%d;", user_id);

    int rc = sqlite3_exec(db, sql, auth_callback, u_data, &err_msg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error in get_account_info: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    return (u_data->user_id != 0); 
}

// --- CORE HANDLERS (Security & Concurrency Focused) ---

// Customer: Create New Account
void handle_create_customer(const char *username, const char *password, char *response) {
    char sql[BUFFER_SIZE];

    snprintf(sql, BUFFER_SIZE,
        "BEGIN; "
        "INSERT INTO Users (username, password, role_id) VALUES ('%s', '%s', 1); "
        "INSERT INTO Accounts (user_id, balance) VALUES (last_insert_rowid(), 0.0); "
        "COMMIT;",
        username, password);

    int rc = db_execute_protected(sql);

    if (rc == 0) {
        int new_user_id = -1;
        sqlite3_stmt *stmt;
        const char *sql_select = "SELECT user_id FROM Users WHERE username = ?;";

        if (sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                new_user_id = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        if (new_user_id != -1) {
             snprintf(response, BUFFER_SIZE, "SUCCESS|%d", new_user_id);
        } else {
             strcpy(response, "ERROR|Account created but failed to retrieve ID.");
        }
    } else if (rc == -2) {
        strcpy(response, "ERROR|System busy. Try again.");
    } else {
        strcpy(response, "ERROR|Account creation failed (Username likely exists).");
    }
}

// Login (Secure with Prepared Statements)
int handle_login(const char *username, const char *password, int requested_role, UserData *result) {
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT user_id, role_id, 0, is_active FROM Users WHERE username=? AND password=?;";
    int rc;
    result->user_id = -1; 
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Prepare Error: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        result->user_id = sqlite3_column_int(stmt, 0);
        result->role_id = sqlite3_column_int(stmt, 1);
        result->is_active = sqlite3_column_int(stmt, 3);
    } else if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL Step Error: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);

    if (result->user_id != -1) {
        // --- Single Session Check ---
        UserData current_status;
        char sql_check[256];
        char *err_msg = 0;

        // Query status (We need to check BEFORE setting, so this must be a separate SELECT)
        // We use a simple select for status (not protected, as it's a read before a write)
        snprintf(sql_check, 256, "SELECT is_logged_in FROM Users WHERE user_id=%d;", result->user_id);

        int is_logged_in_status = 0;
        sqlite3_stmt *check_stmt;
        if (sqlite3_prepare_v2(db, sql_check, -1, &check_stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(check_stmt) == SQLITE_ROW) {
                is_logged_in_status = sqlite3_column_int(check_stmt, 0);
            }
            sqlite3_finalize(check_stmt);
        }

        if (is_logged_in_status == 1) {
             return -4; 
        }

        if (result->role_id != requested_role) return -2;
        if (result->is_active == 0) return -3;

        // --- Set Session Lock (Lock only happens on successful login) ---
        char sql_lock[128];
        snprintf(sql_lock, 128, "UPDATE Users SET is_logged_in=1 WHERE user_id=%d;", result->user_id);
        db_execute_protected(sql_lock); // CRITICAL: Use protected execution for the write operation

        return 1; // Success
    }

    return 0;
}

void clear_session_lock(int user_id) {
    if (user_id > 0) {
        char sql_unlock[128];
        snprintf(sql_unlock, 128, "UPDATE Users SET is_logged_in=0 WHERE user_id=%d;", user_id);
        // This is executed as the child process exits, so protected execution is safest.
        db_execute_protected(sql_unlock);
    }
}

// --- Customer Handlers ---
void handle_view_balance(int user_id, char *response) {
    UserData u_data;
    if (get_account_info(user_id, &u_data)) {
        snprintf(response, BUFFER_SIZE, "SUCCESS|%.2f", u_data.balance);
    } else {
        strcpy(response, "ERROR|Account not found.");
    }
}

void handle_deposit(int user_id, const char *amount_str, char *response) {
    double amount = atof(amount_str);
    if (amount <= 0) {
        strcpy(response, "ERROR|Invalid deposit amount.");
        return;
    }
    char sql[BUFFER_SIZE];
    
    snprintf(sql, BUFFER_SIZE, 
        "BEGIN; "
        "UPDATE Accounts SET balance = balance + %f WHERE user_id = %d; "
        "INSERT INTO Transactions (account_id, type, amount, details) "
        "SELECT account_id, 'DEPOSIT', %f, 'Self Deposit' FROM Accounts WHERE user_id=%d; "
        "COMMIT;",
        amount, user_id, amount, user_id);
    
    int rc = db_execute_protected(sql); 
    
    if (rc == 0) strcpy(response, "SUCCESS|Deposit successful.");
    else if (rc == -2) strcpy(response, "ERROR|System busy. Try again.");
    else strcpy(response, "ERROR|Deposit failed (DB error).");
}

void handle_withdraw(int user_id, const char *amount_str, char *response) {
    double amount = atof(amount_str);
    UserData u_data;
    
    if (amount <= 0 || !get_account_info(user_id, &u_data) || u_data.balance < amount) {
        strcpy(response, "ERROR|Invalid amount or Insufficient funds.");
        return;
    }

    char sql[BUFFER_SIZE];
    
    snprintf(sql, BUFFER_SIZE, 
        "BEGIN; "
        "UPDATE Accounts SET balance = balance - %f WHERE user_id = %d AND balance >= %f; "
        "INSERT INTO Transactions (account_id, type, amount, details) "
        "SELECT account_id, 'WITHDRAW', %f, 'Self Withdrawal' FROM Accounts WHERE user_id=%d; "
        "COMMIT;",
        amount, user_id, amount, amount, user_id);
    
    int rc = db_execute_protected(sql); 

    if (rc == 0) strcpy(response, "SUCCESS|Withdrawal successful.");
    else if (rc == -2) strcpy(response, "ERROR|System busy. Try again.");
    else strcpy(response, "ERROR|Withdrawal failed (DB error).");
}

void handle_transfer(int user_id, const char *target_account_id_str, const char *amount_str, char *response) {
    double amount = atof(amount_str);
    int target_account_id = atoi(target_account_id_str);
    UserData u_data;

    if (amount <= 0 || !get_account_info(user_id, &u_data) || u_data.balance < amount) {
        strcpy(response, "ERROR|Invalid amount or Insufficient funds.");
        return;
    }
    
    char sql[BUFFER_SIZE];
    
    snprintf(sql, BUFFER_SIZE, 
        "BEGIN; "
        "UPDATE Accounts SET balance = balance - %f WHERE user_id = %d AND balance >= %f; "
        "INSERT INTO Transactions (account_id, type, amount, details) "
        "SELECT account_id, 'TRANSFER', %f, 'Transfer OUT to Acc %d' FROM Accounts WHERE user_id=%d; "
        
        "UPDATE Accounts SET balance = balance + %f WHERE account_id = %d; "
        "INSERT INTO Transactions (account_id, type, amount, details) "
        "VALUES (%d, 'TRANSFER', %f, 'Transfer IN from user %d'); "
        
        "COMMIT;",
        amount, user_id, amount, amount, target_account_id, user_id,
        amount, target_account_id,
        target_account_id, amount, user_id);
    
    int rc = db_execute_protected(sql);

    if (rc == 0) strcpy(response, "SUCCESS|Transfer successful.");
    else if (rc == -2) strcpy(response, "ERROR|System busy. Try again.");
    else strcpy(response, "ERROR|Transfer failed (DB error/Target not found).");
}

void handle_view_history(int user_id, char *response) {
    char sql[BUFFER_SIZE];
    char *err_msg = 0;
    UserData u_data = {.details = ""};

    strcpy(u_data.details, "History:\n");

    snprintf(sql, BUFFER_SIZE,
        "SELECT T.* FROM Transactions T "
        "JOIN Accounts A ON T.account_id = A.account_id "
        "WHERE A.user_id = %d ORDER BY T.timestamp DESC LIMIT 10;", user_id);

    int rc = sqlite3_exec(db, sql, history_callback, &u_data, &err_msg);

    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        strcpy(response, "ERROR|Failed to fetch history.");
        return;
    }

    if (strlen(u_data.details) > 9) {
        // Safe string concatenation
        strcpy(response, "SUCCESS|"); 
        strncat(response, u_data.details, BUFFER_SIZE - strlen(response) - 1);
    } else {
        strcpy(response, "SUCCESS|No transactions found.");
    }
}


void handle_change_password(int user_id, const char *new_password, char *response) {
    char sql[BUFFER_SIZE];
    snprintf(sql, BUFFER_SIZE, 
        "UPDATE Users SET password = '%s' WHERE user_id = %d;", new_password, user_id);
    
    int rc = db_execute_protected(sql);
    
    if (rc == 0) strcpy(response, "SUCCESS|Password changed successfully.");
    else strcpy(response, "ERROR|Failed to change password.");
}
// Customer: Apply for a Loan
void handle_apply_loan(int user_id, const char *amount_str, char *response) {
    double amount = atof(amount_str);
    char sql[BUFFER_SIZE];

    if (amount <= 0) {
        strcpy(response, "ERROR|Invalid loan amount.");
        return;
    }

    // Insert the loan application with PENDING status.
    snprintf(sql, BUFFER_SIZE,
        "INSERT INTO Loans (account_id, amount, status) "
        "SELECT account_id, %f, 'PENDING' FROM Accounts WHERE user_id=%d;",
        amount, user_id);

    int rc = db_execute_protected(sql);

    if (rc == 0) strcpy(response, "SUCCESS|Loan application submitted successfully. Status: PENDING.");
    else if (rc == -2) strcpy(response, "ERROR|System busy. Try again.");
    else strcpy(response, "ERROR|Loan submission failed (DB error).");
}

static int loan_list_callback(void *data, int argc, char **argv, char **azColName) {
    UserData *u_data = (UserData *)data;
    char entry[512];

    // Check if space remains in the buffer (BUFFER_SIZE is likely 2048)
    if (strlen(u_data->details) >= BUFFER_SIZE - 512) {
        return 1; // Stop fetching rows if buffer is almost full
    }

    // Format: LOAN_ID | ACCOUNT_ID | AMOUNT | STATUS
    // The query is expected to return: argv[0]=loan_id, argv[1]=account_id, argv[2]=amount, argv[3]=status
    if (argc >= 4) {
        // Build the formatted entry string
        snprintf(entry, 512, "[ID:%s] Acc:%s - $%.2f - Status:%s\n", argv[0], argv[1], atof(argv[2]), argv[3]);

        // Safely append to the main details buffer
        strncat(u_data->details, entry, BUFFER_SIZE - strlen(u_data->details) - 1);
    }
    return 0;
}

void handle_view_pending_loans(char *response) {
    char *err_msg = 0;
    UserData u_data = {.details = ""};

    // Clear response buffer initially
    memset(response, 0, BUFFER_SIZE);

    strcpy(u_data.details, "Pending Loan Applications:\n");

    const char *sql_select =
        "SELECT loan_id, account_id, amount, status FROM Loans WHERE status = 'PENDING' OR status = 'ASSIGNED' ORDER BY loan_id ASC;";

    int rc = sqlite3_exec(db, sql_select, loan_list_callback, &u_data, &err_msg);

    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        // FIX: Ensure error message is explicitly returned
        strcpy(response, "ERROR|Failed to fetch loan list.");
        return;
    }

    if (strlen(u_data.details) > 30) {
        // FIX: Ensure the successful response is built correctly
        strcpy(response, "SUCCESS|");
        strncat(response, u_data.details, BUFFER_SIZE - strlen("SUCCESS|") - 1); // Use correct size calculation
    } else {
        strcpy(response, "SUCCESS|No pending loan applications found.");
    }
}

// Customer: Adding Feedback
void handle_add_feedback(int user_id, const char *message, char *response) {
    char sql[BUFFER_SIZE];

    if (strlen(message) < 5) {
        strcpy(response, "ERROR|Feedback message is too short.");
        return;
    }

    // Insert feedback message. Note: This does not require financial concurrency.
    snprintf(sql, BUFFER_SIZE,
        "INSERT INTO Feedback (user_id, message) VALUES (%d, '%s');",
        user_id, message);

    // Feedback is not a critical financial transaction, but we use protected
    // execution for thread safety when modifying the DB.
    int rc = db_execute_protected(sql);

    if (rc == 0) strcpy(response, "SUCCESS|Feedback submitted. Thank you.");
    else if (rc == -2) strcpy(response, "ERROR|System busy. Try again.");
    else strcpy(response, "ERROR|Feedback submission failed.");
}

// --- Employee Handlers ---
void handle_add_new_customer(const char *username, const char *password, const char *initial_balance_str, char *response) {
    double initial_balance = atof(initial_balance_str);
    char sql[BUFFER_SIZE];

    if (initial_balance < 0) {
        strcpy(response, "ERROR|Initial balance cannot be negative.");
        return;
    }

    snprintf(sql, BUFFER_SIZE,
        "BEGIN; "
        "INSERT INTO Users (username, password, role_id) VALUES ('%s', '%s', 1); "
        "INSERT INTO Accounts (user_id, balance) VALUES (last_insert_rowid(), %f); "
        "COMMIT;",
        username, password, initial_balance);

    int rc = db_execute_protected(sql);

    if (rc == 0) {
        strcpy(response, "SUCCESS|New customer and account created.");
    } else if (rc == -2) {
        strcpy(response, "ERROR|System busy. Try again.");
    } else {
        strcpy(response, "ERROR|Creation failed (Username likely exists).");
    }
}


void handle_view_assigned_loans(int employee_id, char *response) {
    char sql[BUFFER_SIZE];
    char *err_msg = 0;
    UserData u_data = {.details = ""};

    strcpy(u_data.details, "Loans Assigned to You:\n");

    snprintf(sql, BUFFER_SIZE,
        "SELECT loan_id, account_id, amount, status FROM Loans "
        "WHERE assigned_employee_id = %d AND (status = 'ASSIGNED' OR status = 'PROCESSING') ORDER BY loan_id ASC;", employee_id);

    // Reuse the loan_list_callback (defined in previous steps) to format the output
    int rc = sqlite3_exec(db, sql, loan_list_callback, &u_data, &err_msg);

    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        strcpy(response, "ERROR|Failed to fetch assigned loan list.");
        return;
    }

    if (strlen(u_data.details) > 25) {
        strcpy(response, "SUCCESS|");
        strncat(response, u_data.details, BUFFER_SIZE - strlen(response) - 1);
    } else {
        strcpy(response, "SUCCESS|No loans currently assigned to you.");
    }
}

void handle_process_loan_application(const char *loan_id_str, const char *status_str, int employee_id, char *response) {
    int loan_id = atoi(loan_id_str);
    char sql[BUFFER_SIZE];

    if (loan_id <= 0 || (strcmp(status_str, "APPROVED") != 0 && strcmp(status_str, "REJECTED") != 0)) {
        strcpy(response, "ERROR|Invalid Loan ID or status (Use APPROVED or REJECTED).");
        return;
    }

    int rc = -1;

    if (strcmp(status_str, "APPROVED") == 0) {
        // --- Approval Logic: Find loan amount and update account balance ---
        double loan_amount = 0.0;
        int account_id = -1;
        sqlite3_stmt *stmt;

        // 1. Get loan details securely (amount and account_id)
        const char *sql_select = "SELECT amount, account_id FROM Loans WHERE loan_id=? AND status != 'APPROVED';";

        if (sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, loan_id);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                loan_amount = sqlite3_column_double(stmt, 0);
                account_id = sqlite3_column_int(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }

        if (loan_amount > 0 && account_id != -1) {
            // 2. Perform atomic update (update status, credit account, log transaction)
            snprintf(sql, BUFFER_SIZE,
                "BEGIN; "
                "UPDATE Loans SET status = 'APPROVED', assigned_employee_id = %d WHERE loan_id = %d; "
                "UPDATE Accounts SET balance = balance + %f WHERE account_id = %d; "
                "INSERT INTO Transactions (account_id, type, amount, details) VALUES (%d, 'LOAN_CREDIT', %f, 'Loan Approval');"
                "COMMIT;",
                employee_id, loan_id, loan_amount, account_id, account_id, loan_amount);

            rc = db_execute_protected(sql);
        } else {
            strcpy(response, "ERROR|Loan not found or already processed.");
            return;
        }
    } else {
        // --- Rejection Logic: Simple status update ---
        snprintf(sql, BUFFER_SIZE,
            "UPDATE Loans SET status = 'REJECTED', assigned_employee_id = %d WHERE loan_id = %d AND status != 'APPROVED';",
            employee_id, loan_id);

        rc = db_execute_protected(sql);
    }

    if (rc == 0) {
        snprintf(response, BUFFER_SIZE, "SUCCESS|Loan %d processed: %s.", loan_id, status_str);
    } else if (rc == -2) {
        strcpy(response, "ERROR|System busy (Concurrency lock fail). Try again.");
    } else {
        strcpy(response, "ERROR|Failed to update loan status (DB error).");
    }
}

void handle_modify_customer(const char *target_user_id_str, const char *new_password, char *response) {
    int target_user_id = atoi(target_user_id_str);
    char sql[BUFFER_SIZE];

    snprintf(sql, BUFFER_SIZE,
        "UPDATE Users SET password = '%s' WHERE user_id = %d AND role_id = 1;",
        new_password, target_user_id);

    int rc = db_execute_protected(sql);

    if (rc == 0) strcpy(response, "SUCCESS|Customer details modified.");
    else strcpy(response, "ERROR|Failed to modify details (User may not exist or is not a Customer).");
}

void handle_view_passbook(const char *target_user_id_str, char *response) {
    int target_user_id = atoi(target_user_id_str);
    char sql[BUFFER_SIZE];
    char *err_msg = 0;
    UserData u_data = {.details = ""};

    strcpy(u_data.details, "Passbook History:\n");

    snprintf(sql, BUFFER_SIZE,
        "SELECT T.* FROM Transactions T "
        "JOIN Accounts A ON T.account_id = A.account_id "
        "WHERE A.user_id = %d ORDER BY T.timestamp DESC LIMIT 20;", target_user_id);

    int rc = sqlite3_exec(db, sql, history_callback, &u_data, &err_msg);

    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        strcpy(response, "ERROR|Failed to fetch passbook history.");
        return;
    }

    if (strlen(u_data.details) > 17) {
        strcpy(response, "SUCCESS|");
        strncat(response, u_data.details, BUFFER_SIZE - strlen(response) - 1);
    } else {
        strcpy(response, "SUCCESS|No transactions found for that user.");
    }
}


// Manager: Activate/Deactivate Customer Accounts
void handle_activate_deactivate(const char *target_user_id_str, const char *status_str, char *response) {
    int target_user_id = atoi(target_user_id_str);
    int status_val = (strcmp(status_str, "ACTIVATE") == 0) ? 1 : 0;
    char sql[BUFFER_SIZE];

    snprintf(sql, BUFFER_SIZE,
        "UPDATE Users SET is_active = %d WHERE user_id = %d AND role_id = 1;",
        status_val, target_user_id);

    int rc = db_execute_protected(sql);

    if (rc == 0) snprintf(response, BUFFER_SIZE, "SUCCESS|Account %d status set to %s.", target_user_id, status_str);
    else strcpy(response, "ERROR|Failed to modify account status.");
}

// Manager: Assign Loan Application Processes to Employees
void handle_assign_loan(const char *loan_id_str, const char *employee_id_str, char *response) {
    int loan_id = atoi(loan_id_str);
    int employee_id = atoi(employee_id_str);
    char sql[BUFFER_SIZE];

    snprintf(sql, BUFFER_SIZE, 
        "UPDATE Loans SET assigned_employee_id = %d, status = 'ASSIGNED' WHERE loan_id = %d AND status = 'PENDING';", 
        employee_id, loan_id);
    int rc = db_execute_protected(sql);

    if (rc == 0) snprintf(response, BUFFER_SIZE, "SUCCESS|Loan %d assigned to Employee %d.", loan_id, employee_id);
    else strcpy(response, "ERROR|Failed to assign loan (Loan may not be pending or IDs invalid).");
}

void handle_review_feedback(char *response) {
    char sql[BUFFER_SIZE];
    char *err_msg = 0;
    UserData u_data = {.details = ""};

    strcpy(u_data.details, "Customer Feedback:\n");

    const char *sql_select = "SELECT feedback_id, user_id, message, timestamp FROM Feedback ORDER BY timestamp DESC;";

    int rc = sqlite3_exec(db, sql_select, feedback_callback, &u_data, &err_msg);

    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        strcpy(response, "ERROR|Failed to fetch feedback.");
        return;
    }

    if (strlen(u_data.details) > 20) {
        strcpy(response, "SUCCESS|");
        strncat(response, u_data.details, BUFFER_SIZE - strlen(response) - 1);
    } else {
        strcpy(response, "SUCCESS|No feedback found.");
    }
}

void handle_add_new_employee(const char *username, const char *password, char *response) {
    char sql[BUFFER_SIZE];

    // Employee role_id is 2. No account table entry is needed here, just the User entry.
    snprintf(sql, BUFFER_SIZE,
        "BEGIN; "
        "INSERT INTO Users (username, password, role_id) VALUES ('%s', '%s', 2); "
        "COMMIT;",
        username, password);

    int rc = db_execute_protected(sql);

    if (rc == 0) {
        strcpy(response, "SUCCESS|New Bank Employee account created.");
    } else if (rc == -2) {
        strcpy(response, "ERROR|System busy. Try again.");
    } else {
        strcpy(response, "ERROR|Creation failed (Username likely exists).");
    }
}

void handle_admin_modify_user(const char *target_user_id_str, const char *new_password, char *response) {
    int target_user_id = atoi(target_user_id_str);
    char sql[BUFFER_SIZE];

    if (target_user_id <= 0) {
        strcpy(response, "ERROR|Invalid target User ID.");
        return;
    }

    // Update password for any user_id
    snprintf(sql, BUFFER_SIZE,
        "UPDATE Users SET password = '%s' WHERE user_id = %d;",
        new_password, target_user_id);

    int rc = db_execute_protected(sql);

    // Check if any row was affected
    if (rc == 0) {
        // NOTE: A more robust check would use sqlite3_changes() to ensure a row was updated
        strcpy(response, "SUCCESS|Details (Password) modified for user.");
    } else {
        strcpy(response, "ERROR|Failed to modify details (User ID invalid or DB error).");
    }
}

void handle_manage_user_roles(const char *target_user_id_str, const char *new_role_id_str, char *response) {
    int target_user_id = atoi(target_user_id_str);
    int new_role_id = atoi(new_role_id_str);
    char sql[BUFFER_SIZE];

    if (target_user_id <= 0 || new_role_id < 1 || new_role_id > 4) {
        strcpy(response, "ERROR|Invalid User ID or Role ID (must be 1-4).");
        return;
    }

    // Update role for any user_id
    snprintf(sql, BUFFER_SIZE,
        "UPDATE Users SET role_id = %d WHERE user_id = %d;",
        new_role_id, target_user_id);

    int rc = db_execute_protected(sql);

    if (rc == 0) {
        strcpy(response, "SUCCESS|User role updated successfully.");
    } else {
        strcpy(response, "ERROR|Failed to update user role.");
    }
}


void handle_admin_action(const char *action, const char *args[], int user_id, char *response) {
    snprintf(response, BUFFER_SIZE, "SUCCESS|Admin action '%s' by user %d acknowledged.", action, user_id);
}
void handle_manager_action(const char *action, const char *args[], int user_id, char *response) {
    snprintf(response, BUFFER_SIZE, "SUCCESS|Manager action '%s' by user %d acknowledged.", action, user_id);
}
void handle_employee_action(const char *action, const char *args[], int user_id, char *response) {
    snprintf(response, BUFFER_SIZE, "SUCCESS|Employee action '%s' by user %d acknowledged.", action, user_id);
}

void handle_child_process(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    char response[BUFFER_SIZE] = "ERROR|Unknown Request.";
    ssize_t bytes_read;
    
    // 1. Declare user_id here to ensure global scope for cleanup
    int user_id = -1; 
    const char *final_action = "UNKNOWN";
    
    bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("PID %d: Received: '%s'\n", getpid(), buffer);

        char *tokens[MAX_TOKENS];
        int i = 0;
        tokens[i] = strtok(buffer, "|");
        while (tokens[i] != NULL && i < MAX_TOKENS - 1) {
            tokens[++i] = strtok(NULL, "|");
        }
        int num_tokens = i;

        if (num_tokens >= 3) {
            const char *action = tokens[0];
            int role_id = atoi(tokens[1]);
            user_id = atoi(tokens[2]); // Assign to the function-scoped user_id
	    final_action = action;

            // --- Single Session Active Check (for all actions EXCEPT login/logout/create) ---
            if (strcmp(action, "LOGIN") != 0 && strcmp(action, "LOGOUT") != 0 && strcmp(action, "CREATE_CUSTOMER") != 0) {
                
                char sql_check[256];
                int is_logged_in_status = 0;
                
                // Fetch current session status
                snprintf(sql_check, 256, "SELECT is_logged_in FROM Users WHERE user_id=%d;", user_id);
                sqlite3_stmt *check_stmt;
                if (sqlite3_prepare_v2(db, sql_check, -1, &check_stmt, NULL) == SQLITE_OK) {
                    if (sqlite3_step(check_stmt) == SQLITE_ROW) {
                        is_logged_in_status = sqlite3_column_int(check_stmt, 0);
                    }
                    sqlite3_finalize(check_stmt);
                }
                
                // If status is 0 (logged out), the session is invalid/expired. Deny the request.
                if (is_logged_in_status == 0) {
                    strcpy(response, "ERROR|SESSION_EXPIRED");
                    goto cleanup_and_exit; // Jump to the end of the function
                }
                
                // If status is 1 (logged in), refresh the lock (a benign UPDATE)
                else {
                    char sql_refresh[128];
                    snprintf(sql_refresh, 128, "UPDATE Users SET is_logged_in=1 WHERE user_id=%d;", user_id);
                    db_execute_protected(sql_refresh);
                }
            }
            // --- End Session Check ---

            // 0. LOGOUT (Must be handled first to trigger cleanup)
	    if (strcmp(action, "LOGOUT") == 0 && num_tokens == 3) {
                handle_logout(response,user_id);
            }
            
            // 0. New Customer Creation
            else if (strcmp(action, "CREATE_CUSTOMER") == 0 && num_tokens == 4 && role_id == 1) {
                handle_create_customer(tokens[2], tokens[3], response);
            }

            // 0. Login Check
            else if (strcmp(action, "LOGIN") == 0 && num_tokens == 4) {
                UserData u_data;
                int login_status = handle_login(tokens[2], tokens[3], role_id, &u_data);
                if (login_status == 1) snprintf(response, BUFFER_SIZE, "SUCCESS|%d|%d", u_data.user_id, u_data.role_id);
                else if (login_status == -2) strcpy(response, "ERROR|Role mismatch.");
                else if (login_status == -3) strcpy(response, "ERROR|Account deactivated.");
		else if (login_status == -4) strcpy(response, "ERROR|ALREADY_LOGGED_IN");
                else strcpy(response, "ERROR|Invalid credentials or SQL error.");
            }
            
            // 1. Customer Feature Integration (Role 1)
            else if (role_id == 1) {
                if (strcmp(action, "VIEW_BALANCE") == 0) handle_view_balance(user_id, response);
                else if (strcmp(action, "DEPOSIT") == 0) handle_deposit(user_id, tokens[3], response);
                else if (strcmp(action, "WITHDRAW") == 0) handle_withdraw(user_id, tokens[3], response);
                else if (strcmp(action, "TRANSFER") == 0) handle_transfer(user_id, tokens[3], tokens[4], response);
                else if (strcmp(action, "VIEW_HISTORY") == 0) handle_view_history(user_id, response);
                else if (strcmp(action, "CHANGE_PASS") == 0) handle_change_password(user_id, tokens[3], response);
                else if (strcmp(action, "APPLY_LOAN") == 0 && num_tokens == 4) handle_apply_loan(user_id, tokens[3], response); 
		else if (strcmp(action, "ADD_FEEDBACK") == 0 && num_tokens == 4) handle_add_feedback(user_id, tokens[3], response);
            }
            
            // 2. Employee Feature Integration (Role 2)
	    else if (role_id == 2) {
                if (strcmp(action, "ADD_CUSTOMER") == 0 && num_tokens == 6) handle_add_new_customer(tokens[3], tokens[4], tokens[5], response);
                else if (strcmp(action, "MOD_CUSTOMER") == 0 && num_tokens == 5) handle_modify_customer(tokens[3], tokens[4], response);
                else if (strcmp(action, "VIEW_PASSBOOK") == 0 && num_tokens == 4) handle_view_passbook(tokens[3], response);
		else if (strcmp(action, "VIEW_ASSIGNED_LOANS") == 0 && num_tokens == 3) handle_view_assigned_loans(user_id, response);
                else if (strcmp(action, "PROCESS_LOAN") == 0 && num_tokens == 5) handle_process_loan_application(tokens[3], tokens[4], user_id, response);
                else { handle_employee_action(action, (const char**)&tokens[3], user_id, response); }
            }

            // 3. Manager Feature Integration (Role 3)
	    else if (role_id == 3) {
                if (strcmp(action, "ACT_DEACT_ACC") == 0 && num_tokens == 5) handle_activate_deactivate(tokens[3], tokens[4], response);
		else if (strcmp(action, "VIEW_LOANS") == 0 && num_tokens == 3) handle_view_pending_loans(response);
                else if (strcmp(action, "ASSIGN_LOAN") == 0 && num_tokens == 5) handle_assign_loan(tokens[3], tokens[4], response);
                else if (strcmp(action, "REVIEW_FEEDBACK") == 0 && num_tokens == 3) handle_review_feedback(response);
                else if (strcmp(action, "CHANGE_PASS") == 0 && num_tokens == 4) handle_change_password(user_id, tokens[3], response);
                else { handle_manager_action(action, (const char**)&tokens[3], user_id, response); }
            }

            // 4. Admin Feature Integration (Role 4)
	    else if (role_id == 4) {
                if (strcmp(action, "ADD_EMPLOYEE") == 0 && num_tokens == 5) {
                    // Format: ADD_EMPLOYEE|4|ADM_ID|USERNAME|PASSWORD
                    handle_add_new_employee(tokens[3], tokens[4], response);
                } else if (strcmp(action, "MOD_USER_DETAILS") == 0 && num_tokens == 5) {
                    // Format: MOD_USER_DETAILS|4|ADM_ID|TARGET_USER_ID|NEW_PASS
                    handle_admin_modify_user(tokens[3], tokens[4], response);
                } else if (strcmp(action, "MANAGE_ROLES") == 0 && num_tokens == 5) {
                    // Format: MANAGE_ROLES|4|ADM_ID|TARGET_USER_ID|NEW_ROLE_ID
                    handle_manage_user_roles(tokens[3], tokens[4], response);
                } else if (strcmp(action, "CHANGE_PASS") == 0 && num_tokens == 4) {
                    // Format: CHANGE_PASS|4|ADM_ID|NEW_PASS (Self-service)
                    handle_change_password(user_id, tokens[3], response);
                } else {
                    handle_admin_action(action, (const char**)&tokens[3], user_id, response);
                }
            }
        }
    }
    
cleanup_and_exit: // <-- GOTO TARGET
    // Clean up session and exit child process
	int session_user_id = user_id; 

	send(client_fd, response, strlen(response), 0);
	close(client_fd);

	printf("Child PID %d finished and exiting.\n", getpid());
	exit(0);
}


// --- Main Server Request Handler ---


int main() {
    struct sigaction sa;
    sa.sa_handler = sigchld_handler; 
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) { perror("sigaction failed"); return 1; }

    if (db_init() != 0) return 1;

    int sockfd, new_fd;  
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t sin_size;
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { perror("socket failed"); return 1; }
    int yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    
    server_addr.sin_family = AF_INET; server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    memset(&(server_addr.sin_zero), '\0', 8); 
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind failed"); close(sockfd); return 1;
    }
    
    if (listen(sockfd, BACKLOG) == -1) { perror("listen failed"); close(sockfd); return 1; }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        sin_size = sizeof(struct sockaddr_in);
        if ((new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size)) == -1) {
            perror("accept failed"); continue;
        }

        printf("Connection from %s:%d. Forking process (PID %d)...\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), getpid());

        if (fork() == 0) { 
            close(sockfd);
            handle_child_process(new_fd);
        } else {
            close(new_fd);
        }
    }
    
    db_close();
    close(sockfd);
    return 0;
}
