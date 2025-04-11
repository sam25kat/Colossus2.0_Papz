import sqlite3

DATABASE = "file_logs.db"  # Replace with your actual database file

def add_column_to_users():
    """Add a new column 'metadata' to the 'files' table."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    try:
        c.execute("ALTER TABLE research_approvals ADD COLUMN incentive_provided INTEGER DEFAULT 0;")
        conn.commit()
        print("Column  added successfully.")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def show_all_data(table_name):
    """Fetch and display all records from the specified table."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    try:
        c.execute(f"SELECT * FROM {table_name};")
        records = c.fetchall()

        column_names = [desc[0] for desc in c.description]

        if records:
            print(f"\nData from '{table_name}':")
            print(", ".join(column_names))  # Print column headers
            for record in records:
                print(record)
        else:
            print(f"No data found in the table '{table_name}'.")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def delete_all_data_from_table(table_name):
    """Delete all data from the specified table."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    try:
        c.execute(f"DELETE FROM {table_name};")
        conn.commit()
        print(f"All data from the table '{table_name}' has been deleted.")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def show_all_tables():
    """List all tables in the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = c.fetchall()
        if tables:
            print("\nTables in the database:")
            for table in tables:
                print(f"- {table[0]}")
        else:
            print("No tables found in the database.")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def show_table_schema(table_name):
    """Display the schema of a given table."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    try:
        c.execute(f"PRAGMA table_info({table_name});")
        schema = c.fetchall()
        if schema:
            print(f"\nSchema of '{table_name}':")
            print("CID | Name | Type | NotNull | Default | PrimaryKey")
            for col in schema:
                print(" | ".join(str(x) for x in col))
        else:
            print(f"No schema found for table '{table_name}'.")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def create_research_approvals_table():
    """Create the research_approvals table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    try:
        c.execute("""
            CREATE TABLE IF NOT EXISTS metadata_record (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                category TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metdata TEXT
                
            );
        """)
        conn.commit()
        print("Table 'research_approvals' created successfully (if it didn't already exist).")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def rename_column(table_name, old_column_name, new_column_name):
    """Rename a column in a table."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    try:
        c.execute(f"ALTER TABLE {table_name} RENAME COLUMN {old_column_name} TO {new_column_name};")
        conn.commit()
        print(f"Column '{old_column_name}' renamed to '{new_column_name}' in table '{table_name}'.")
    except sqlite3.OperationalError as e:
        print(f"Error: {e}")
    finally:
        conn.close()


# Example usage
#add_column_to_users()
#show_all_tables()
show_all_data("metadata_record")
# delete_all_data_from_table("users")
#show_table_schema("files")
#create_research_approvals_table()
#rename_column("table_name","metadata","metdata")



