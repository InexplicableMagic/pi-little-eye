import numpy as np
from datetime import datetime, timedelta
import sqlite3
import uuid
import re
import os
import string
import random
import bcrypt
import binascii
import hashlib
import ipaddress
import time
import secrets
import sys
import threading

class DBConfigHandler:
    
    MAX_PASS_LENGTH = 100
    MAX_USERNAME_LENGTH = 100
    VALID_PERMISSIONS = ['admin', 'viewer']
    IPV4_WILDCARD_PATTERN = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){0,3}\*$'
    IPV6_WILDCARD_PATTERN = r'^(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:(?:[a-fA-F\d]{1,4})\:){0,7}(?:\*|(?:[a-fA-F\d]{1,3})\*))$'
    
    def __init__(self, db_path, factory_reset):
        self.db_path = db_path
        
        # On factory reset, delete the existing database and then recreate it
        if factory_reset:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        
        self.initialise_database()
        
        self.delete_old_log_lines()                
        self.next_log_line_delete_time = int(time.time()) + 86400
        self.config_change_lock = threading.Lock()
        
        if factory_reset:
            self.write_log_line( 'warning', True, '','', 'factory_reset', 'Factory reset via command line' )
         
    def read_only_connection(self):
        return sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        
    def initialise_database(self):
        # Create the database if it doesn't exist
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Authentication table - stores usernames and passwords of camera users
        # disabled - whether the account is locked
        # bad_pass_attempts - number of consecutive failed login attempts for this account
                
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS authentication (
                username TEXT PRIMARY KEY NOT NULL UNIQUE,
                permissions TEXT NOT NULL,
                pass_bcrypt TEXT NOT NULL,
                salt TEXT NOT NULL,
                disabled BOOLEAN NOT NULL DEFAULT FALSE,
                bad_pass_attempts INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # List of active user web sessions currently logged in and authorised by cookie
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY NOT NULL UNIQUE,
                username NOT NULL,
                token_sha512 TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Application keys for API camera viewers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS appkeys (
                appkey TEXT PRIMARY KEY NOT NULL UNIQUE,
                secret_sha512 TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # List of issued challege UUIDs. Used to verify a user can receive data at their perported IP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenge_response (
                response TEXT,
                expiry TIMESTAMP
            )
        ''')
        
        # Configuration parameters as key/value pairs (with strong typing for the value)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS parameters (
                key TEXT PRIMARY KEY NOT NULL UNIQUE,
                datatype TEXT,
                value TEXT
            )
        ''')
        
        # List of IPs that are permitted to view the camera or else are blacklisted
        # If whitelisted is False, then the IP is blacklisted
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_allow_list (
            ip TEXT NOT NULL,
            whitelisted BOOLEAN CHECK (whitelisted IN (0, 1))
        );
        ''')
        
        # Level: warning, info or error
        # Alert: true if the log line should be specifically highlighted to an admin on login, such as a security problem
        # Username: that attempted the action or username presented on login
        # IP route: comma separated list of IPs associated with the user attempting the action
        # type: Type of log line
        # message: English text description of the log line
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            ts TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            level TEXT NOT NULL,
            alert BOOLEAN DEFAULT FALSE,
            username TEXT,
            ip_route TEXT,
            type TEXT NOT NULL,
            message TEXT NOT NULL
        );
        ''')
        
        # Version number of the software this database was created with 
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS created_with_version (
                created_with_version TEXT
            )
        ''')
        
        cursor.execute('''
            INSERT INTO created_with_version (created_with_version)
            SELECT '1.0.0'
            WHERE NOT EXISTS (SELECT 1 FROM created_with_version)
        ''')

        conn.commit()
        conn.close()
                
        # If the parameters table is emtpy, it's the first time the script has been run so set defaults in the DB
        if self.is_parameters_table_empty():
            # Initial authentication state requires a password to be set
            self.insert_or_update_parameter( 'auth_state', 'string', 'nopass' )
            # Disable enforcement of IP whitelist and blocklist by default
            self.disable_ip_whitelist_and_blocklist()
            # Set the initial IP whitelist and blocklist
            self.set_ip_allow_list( [ '192.168.*', '10.*', '172.16.*', 'fc*', 'fd*', '127.0.0.1' ], [] )
            # Expire user login sessions initially after 30 days - forces password re-entry after this number of days
            self.insert_or_update_parameter( 'max_session_age', 'int', 30 )
            # Disable non-admin accounts after this number of bad password attempts in a row
            self.insert_or_update_parameter( 'disable_account_after_bad_pass_attempts', 'int', 10 )
            #Some Raspberry Pis can have more than one camera - this stores which camera we are looking at
            self.insert_or_update_parameter( 'cam_number', 'int', 0 )
            # The currently user selected resolution for the camera
            self.insert_or_update_parameter( 'cam_res_width', 'int', 640 )
            self.insert_or_update_parameter( 'cam_res_height', 'int', 480 )
            # Delete log lines after this number of days
            self.insert_or_update_parameter( 'delete_log_after_days', 'int', 90 )
            # Default image rotation in degrees: 0, 90, 180 or 270
            self.insert_or_update_parameter( 'image_rotation', 'int', 0 )
            # Default timestamp text scale multiplier, sets the size of the timestamp text
            self.insert_or_update_parameter( 'timestamp_scale_factor', 'string' , 'medium')
            # Default timestamp text position
            self.insert_or_update_parameter( 'timestamp_position', 'string' , 'bottom-right')
            # Whether the timestamp should be displayed
            self.insert_or_update_parameter( 'display_timestamp', 'bool', True )

        ip_lists = self.get_ip_allow_list()
        self.ip_response = dict()
        self.ip_white_list = ip_lists['whitelisted']
        self.ip_black_list = ip_lists['blacklisted']
        self.enforce_ip_whitelist = self.get_parameter_value('enforce_ip_whitelist')
        self.enforce_ip_blocklist = self.get_parameter_value('enforce_ip_blocklist')
    
    def disable_ip_whitelist_and_blocklist( self ):
        self.insert_or_update_parameter( 'enforce_ip_whitelist', 'bool', False )
        self.insert_or_update_parameter( 'enforce_ip_blocklist', 'bool', False )
        self.enforce_ip_whitelist = self.get_parameter_value('enforce_ip_whitelist')
        self.enforce_ip_blocklist = self.get_parameter_value('enforce_ip_blocklist')
     
    def write_log_line( self, level, alert, username, ip_route, log_type, message ):
        
        # Expire old log lines once per day
        if time.time() > self.next_log_line_delete_time:
            self.delete_old_log_lines()                
            self.next_log_line_delete_time = int(time.time()) + 86400
       
        try:
            # Avoid the caller being able to evade a log line being written by passing a bad username
            # Attempt to safely write to the log whatever they passed in
            # Some types of log lines can genuinely not have username where the user has not yet authenticated 
            if username is None:
                username = '';
            else:
                if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):   
                    username = str(username)
                    username = username[ :DBConfigHandler.MAX_USERNAME_LENGTH ]
            
            # Set a maximum log message limit to avoid overflows on bad strings
            if message is None or message == '':
                message = 'Expecting a log message but unexpectedly none set.'
            if len(message) > 4096:
                message = message[:4096]+ ' ... log message truncated at 4096 characters'

            insert_log_line_sql = "INSERT INTO log (level, alert, username, ip_route, type, message) VALUES( ?,?,?,?,?,? )"
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(insert_log_line_sql, (level, alert, username, ip_route, log_type, message))
            conn.commit()
        except Exception as e:
            print(f"An error occurred (write_log_line): {e}", file=sys.stderr)
        finally:
            if conn:
               conn.close()    
    
    # Roll off old log lines
    # If full_clear is True then deletes all log lines
    def delete_old_log_lines( self, full_clear = False ):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            min_time = datetime.now() - timedelta(days=self.get_parameter_value('delete_log_after_days') )
            if full_clear:
                cursor.execute('DELETE FROM log;')
            else:
                cursor.execute('DELETE FROM log WHERE ts < ?;', (min_time,) )
            conn.commit()
        except Exception as e:
            print(f"An error occurred (delete_old_log_lines): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (delete_old_log_lines): {e}" )
        finally:
            if conn:
               conn.close()
    
    # Retrieve log lines, optionally from a specific point in the log
    # from_line is an ID number before which we want to retrieve log lines
    # up to a limit (implements paging)    
    def get_logs_paged(self, from_line=None, page_size=100):
    
        if from_line is not None:
            try:
                from_line = int(from_line)
            except:
                from_line = None
                
        try:
            conn = self.read_only_connection()
            cursor = conn.cursor()

            if from_line is None:
                sql = "SELECT id, ts, level, alert, username, ip_route, type, message FROM log ORDER BY id DESC LIMIT ?";
                cursor.execute(sql, (page_size,))
            else:
                sql = "SELECT id, ts, level, alert, username, ip_route, type, message FROM log WHERE id <= ? ORDER BY id DESC LIMIT ?";
                cursor.execute(sql, (from_line, page_size))
            
            results = cursor.fetchall()
            
            # Get min/max stats
            sql_stats = "SELECT min(id), max(id) FROM log";
            cursor.execute(sql_stats)
            min_max = cursor.fetchone()            
            return (results, min_max[0], min_max[1])
        except Exception as e:
            print(f"An error occurred (get_logs_paged): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (get_logs_paged): {e}" )
        finally:
            if conn:
               conn.close()  

    # True if the app has not yet been configured with an initial user account
    def is_app_in_unathenticated_state(self):
        if self.is_pass_table_empty() and self.get_parameter_value('auth_state') == 'nopass':
            return True
        else:
            return False
    
    #Is it a valid IP range e.g. 192.168.* or fc00:*
    def is_valid_ipv4_or_ipv6_wildcard_range(ip_address):
        ip_address = ip_address.strip().lower()
        if ip_address is None:
            return False
        if len(ip_address) < 1:
            return False
        # Don't allow wildcarding everything
        if ip_address == '*':
            return False
        
        if re.match(DBConfigHandler.IPV4_WILDCARD_PATTERN, ip_address) or re.match(DBConfigHandler.IPV6_WILDCARD_PATTERN, ip_address):
            return True
        
        return False
    
    # Expands out an IPv6 address with an optional wildcard character on the end
    # Assumes a valid ipv6 address otherwise returns itself
    def expand_ipv6_with_wildcard(ip_address):
        ip_address = ip_address.strip().lower()
        try:
            if ':' in ip_address:
                expanded_addess = [  ]
                ip_address_parts = ip_address.split(':')
                for part in ip_address_parts:
                    if '*' not in part:
                        part_len = len(part)
                        if part_len > 4:
                            return None
                        if part_len == 0:
                            expanded_addess.append( '0000' )
                        elif part_len == 4:
                            expanded_addess.append( part )
                        else:
                            expanded_addess.append( str(('0'*(4-part_len)))+part )
                            
                    else:
                        expanded_addess.append( part )
               
                return ':'.join( expanded_addess )
        except Exception as e:
            return ip_address
            
        return ip_address
        
    
    # Is it a valid whole IP address (either IPv4 or IPv6)
    def is_valid_ip_address(ip_address):
        try:
            if ip_address is None:
                return False
            if not isinstance(ip_address, str):
                return False
            ip_address = ip_address.strip()
            if len( ip_address ) < 1 or len(ip_address) > 39:
                return False
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    #Expands out condensed IPV6 addresses and does nothing to IPV4
    #Also checks the IP is valid and returns None if not
    def explode_ipv6( addr ):
        try:
            addr = ipaddress.ip_address(addr)
            return addr.exploded
        except Exception as e:
            return None
    
    
    def ip_matches_wildcard_list(ip_to_check, wildcard_list):
        
        if ip_to_check is None:
            return False
        
        ip_to_check = ip_to_check.lower().strip()
        
        if len(ip_to_check) < 1 or len(ip_to_check) > 39:
            return False
        
        ip_to_check = DBConfigHandler.explode_ipv6( ip_to_check )
        if ip_to_check is None:
            return False
        
        for ip_range in wildcard_list:
            if ip_range.endswith( '*' ):
                sans_wildcard_char = ip_range[:-1]
                if ip_to_check.startswith( sans_wildcard_char ):
                    return True
            else:
                if ip_to_check == ip_range:
                    return True

        return False
                
    # Accepts a list of IP addresses
    # Returns True if every IP passed on is on the whitelist and none of them are on the blacklist
    def is_ip_list_allowed( self, ip_list_to_check ):
    
            if len( self.ip_black_list ) > 0:
                if self.enforce_ip_blocklist:
                    for ip in ip_list_to_check:
                        if DBConfigHandler.ip_matches_wildcard_list( ip, self.ip_black_list ):
                            return False
            if len( self.ip_white_list ) > 0:
                if self.enforce_ip_whitelist:
                    for ip in ip_list_to_check:
                        if not DBConfigHandler.ip_matches_wildcard_list( ip, self.ip_white_list ):
                            return False
            
            return True
     

    # Generate a new salt value and use it to generate a password hash
    def make_bcrypt_pass( password ):
        salt = bcrypt.gensalt()
        hex_hashed = DBConfigHandler.make_bcrypt_pass_with_salt( password, salt )
        hex_salt = binascii.hexlify(salt).decode('utf-8')
        return hex_hashed, hex_salt
    
    # Use the exiting salt value encoded in hex to make a password hash
    def make_bcrypt_pass_with_hexsalt( password, hex_salt ):
        salt_bytes = binascii.unhexlify(hex_salt)
        return DBConfigHandler.make_bcrypt_pass_with_salt( password, salt_bytes )
        
    # Use the exiting salt value (in binary) to make a password hash
    def make_bcrypt_pass_with_salt( password, salt ):
        password_bytes = password.encode('utf-8')
        hashed = bcrypt.hashpw(password_bytes, salt)
        hex_hashed = binascii.hexlify(hashed).decode('utf-8')
        return hex_hashed 
        
    def test_bcrypt_password(password, hex_hash, hex_salt):
        salt_bytes = binascii.unhexlify(hex_salt)
        password_bytes = password.encode('utf-8')
        new_hash = bcrypt.hashpw(password_bytes, salt_bytes)
        new_hex_hash = binascii.hexlify(new_hash).decode('utf-8')
        
        return new_hex_hash == hex_hash
        
    # Considerably faster than bcrypt
    # Used for user sessions
    def sha512_hash(item):
        h = hashlib.sha512(item.encode()) 
        return str(h.hexdigest())
        
    def verify_password( self, username, test_password ):
        if username is None:
            return False
        if test_password is None:
            return False
        if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
            return False
        if not DBConfigHandler.validate_utf8_string( test_password, max_length=DBConfigHandler.MAX_PASS_LENGTH ):
            return False
        
        username = username.lower()
        if not self.test_user_exists( username ):
            return False
            
        pass_result = self.get_pass_auth( username );
        if pass_result is not None:
            pass_bcrypt, salt = pass_result;
            if DBConfigHandler.test_bcrypt_password( test_password, pass_bcrypt, salt ):
                self.increment_reset_bad_pass_attempts( username, reset=True )
                return True
            else:
                self.increment_reset_bad_pass_attempts( username )
                pass
        return False


    def is_valid_utf8(s):
        try:
            s.encode('utf-8').decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False
    
    def is_printable(s):
        return all(char in string.printable for char in s)
    
    def validate_utf8_string(s, min_length=1, max_length=100):
        if s is None:
            return False
        if not isinstance(s, str):
            return False
        if len(s) < min_length or len(s) > max_length:
            return False
        if not DBConfigHandler.is_valid_utf8(s):
            return False
        if not DBConfigHandler.is_printable(s):
            return False
        return True
        
    def is_uuid_valid( the_uuid ):
        if the_uuid is None:
            return False
        if not isinstance(the_uuid, str):
            return False
        if not DBConfigHandler.is_valid_utf8( the_uuid ):
            return False
        if not DBConfigHandler.is_printable(the_uuid):
            return False
        if len(the_uuid) != 36:
            return False
        regex = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', re.I)
        return bool(regex.match(the_uuid))
        
    def is_secret_valid( the_secret ):
        if the_secret is None:
            return False
        if not isinstance(the_secret, str):
            return False
        if not DBConfigHandler.is_valid_utf8( the_secret ):
            return False
        if not DBConfigHandler.is_printable(the_secret):
            return False
        if len(the_secret) != 32:
            return False
        regex = re.compile(r'^[0-9a-fA-F]{32}$', re.I)
        return bool(regex.match(the_secret))
        
    
    def is_parameters_table_empty( self ):
        return self.is_table_empty( "parameters" )
        
    def is_pass_table_empty( self ):
        return self.is_table_empty( "authentication" )
    
    def is_table_empty(self, table_name):
        conn = None
        try:
            # Query to count the number of rows in the table
            conn = self.read_only_connection()
            cursor = conn.cursor()
            if not table_name.isalnum() and not all(c in ['_'] for c in table_name if not c.isalnum()):
                raise ValueError(f"Invalid table name {table_name}") 
            query = f"SELECT COUNT(*) FROM [{table_name}]"
            cursor.execute(query)
            # Fetch the result
            count = cursor.fetchone()[0]
            # If count is 0, the table is empty
            return count == 0
        except Exception as e:
            print(f"Exception: (is_table_empty) {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"Exception: (is_table_empty) {e}" )
            return None
        finally:
            if conn:
                conn.close()
            
    # Adds a parameter to the parameters table. Returns true if successful
    def insert_or_update_parameter(self, key, datatype, value):
        conn = None
                  
        if datatype == 'bool':
            if not isinstance( value, bool ):
                raise ValueError( "Bad value type for parameter insert. Expected boolean." )
            if value:
                value = 'true'
            else:
                value = 'false'
        elif datatype == 'string':
            if not isinstance( value, str ):
                raise ValueError( "Bad value type for parameter insert. Expected string" )
        elif datatype == 'int':
            if not isinstance( value, int ):
                raise ValueError( "Bad value type for parameter insert. Expected int" )
            value = str( value )
        elif datatype == 'float':
            if not isinstance( value, float ):
                 raise ValueError( "Bad value type for parameter insert. Expected float" )
            value=str( value )
        else:
            raise ValueError( "Bad datatype for parameter insert" )
            
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # Use INSERT OR REPLACE to update if exists or insert if not      
            cursor.execute('DELETE FROM parameters where key = ?', (key,))    
            cursor.execute('INSERT INTO parameters (key, datatype, value) VALUES (?, ?, ?)', (key, datatype, value))
            conn.commit()
            return True
        except Exception as e:
            print(f"Exception (insert_or_update_parameter) {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"Exception (insert_or_update_parameter) {e}" )
            return False
        finally:
            if conn:
                 conn.close()
            
    # Gets a parameter by key and returns None if it doesn't exist    
    def get_parameter_value(self, key):
        conn = None
            
        try:
            conn = self.read_only_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT value, datatype FROM parameters WHERE key = ?", (key,))
            result = cursor.fetchone()
            if not result or len(result) != 2:
                return None
            
            value = result[0]
            datatype = result[1]
                        
            if datatype == 'bool':
                if value == 'true':
                    return True
                else:
                    return False
            elif datatype == 'int':
                return int( value )
            elif datatype == 'float':
                return float( value )
            else:
                return str(value)
                
        except Exception as e:
            print(f"An error occurred (get_parameter_value): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (get_parameter_value): {e}" )
            return None
        finally:
            if conn:
               conn.close() 
            
    def expire_challenge_response(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM challenge_response WHERE expiry < CURRENT_TIMESTAMP')
            conn.commit()
        except Exception as e:
            print(f"An error occurred (expire_challenge_response): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (expire_challenge_response): {e}" )
            return None   
        finally:
            if conn:
                conn.close()
    
    # Adds a token we require the authenticating user to send back to us      
    def generate_challenge_response(self):
        conn = None
        self.expire_challenge_response( )
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            response_uuid = secrets.token_hex(16)
            expiry_timestamp = datetime.now() + timedelta(minutes=5)
            cursor.execute('INSERT INTO challenge_response (response, expiry) VALUES ( ?, ? )', 
                            (response_uuid, expiry_timestamp))
            # Commit the transaction and close the connection
            conn.commit()
            return response_uuid;
        except Exception as e:
            print(f"An error occurred (generate_challenge_response): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (generate_challenge_response): {e}" )
            return None   
        finally:
            if conn:
                conn.close()
    
        
    def test_user_exists( self, username ):
        if DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
            try:
                conn = self.read_only_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM authentication WHERE username = ?", (username,))
                result = cursor.fetchone()[0]
                return result > 0
            except Exception as e:
                print(f"An error occurred  (test_user_exists): {e}", file=sys.stderr)
                self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (test_user_exists): {e}" )
                return False   
            finally:
                if conn:
                    conn.close()
   
    def get_pass_auth( self, username ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
            
            max_bad_pass_attempts = int( self.get_parameter_value( 'disable_account_after_bad_pass_attempts' ) )
                
            username = username.lower()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE authentication SET disabled=TRUE WHERE bad_pass_attempts >= ? AND permissions != 'admin'", (max_bad_pass_attempts,))
            query_exists = "SELECT pass_bcrypt, salt FROM authentication WHERE username = ? AND disabled = FALSE"
            cursor.execute(query_exists, (username,))
            result = cursor.fetchone()
            conn.commit()
            return result            
        except Exception as e:
            print(f"An error occurred (get_pass_auth): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (get_pass_auth): {e}" )
            return None   
        finally:
            if conn:
                conn.close()
    
    def is_account_locked( self, username ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
            
            if not self.test_user_exists( username ):
                raise ValueError( "Username does not exist" )
            
            max_bad_pass_attempts = int( self.get_parameter_value( 'disable_account_after_bad_pass_attempts' ) )
                
            username = username.lower()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE authentication SET disabled=TRUE WHERE bad_pass_attempts >= ? AND permissions != 'admin'", (max_bad_pass_attempts,))
            query_disabled = "SELECT disabled FROM authentication WHERE username = ?"
            cursor.execute(query_disabled, (username,))
            result = cursor.fetchone()
            conn.commit()
            if result is not None:
                return result[0] == True
            else:
                return False  # Return False if the username doesn't exist           
        except Exception as e:
            print(f"An error occurred (is_account_locked): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (is_account_locked): {e}" )
            return None   
        finally:
            if conn:
                conn.close()
    
    
    def lock_unlock_delete_account( self, username, action):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                    raise ValueError( "Username is invalid" )

            username = username.lower()
            if not self.test_user_exists( username ):
                raise ValueError( "Username does not exist" )        
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if action=='lock':
                cursor.execute("UPDATE authentication SET disabled=TRUE WHERE username=?", (username,))
            elif action=='unlock':
                cursor.execute("UPDATE authentication SET disabled=FALSE,bad_pass_attempts=0 WHERE username=?", (username,))
            elif action=='delete':
                cursor.execute("DELETE FROM authentication WHERE username=?", (username,))
            else:
                raise ValueError( "Incorrect action. Must be lock, unlock or delete." )  
            conn.commit()
            conn.close()
            conn = None
            if action=='lock' or action=='delete':
                self.remove_all_user_sessions( username )
        except Exception as e:
            print(f"An error occurred (lock_unlock_delete_account): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (lock_unlock_delete_account): {e}" )
            return None   
        finally:
            if conn:
                conn.close()

    #Lists all usernames, permissions and whether they currently have any authenticated sessions
    def list_all_usernames( self ):
        conn = None
        try:
            conn = self.read_only_connection()
            cursor = conn.cursor()
            username_listing_sql = """
                SELECT 
                    a.username,
                    a.permissions,
                    CASE
                        WHEN a.disabled == 1 THEN 'yes'
                        ELSE 'no'
                    END AS disabled,
                    CASE
                        WHEN MAX(s.username) IS NOT NULL THEN 'yes'
                        ELSE 'no'
                    END AS has_active_session
                FROM 
                    authentication a
                LEFT JOIN 
                    sessions s ON a.username = s.username
                GROUP BY 
                    a.username, a.permissions;
            """
            cursor.execute(username_listing_sql)
            result = cursor.fetchall()
            result_obj = [  ]
            for user_data in result:
                result_obj.append( { 'username': user_data[0], 'permissions': user_data[1], 'disabled': user_data[2], 'active_sessions': user_data[3] } )
            return result_obj            
        except Exception as e:
            print(f"An error occurred (list_all_username): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (list_all_username): {e}" )
            return [ ]   
        finally:
            if conn:
                conn.close()
    
    def list_all_app_keys( self ):
        conn = None
        try:
            conn = self.read_only_connection()
            cursor = conn.cursor()
            app_key_listing_sql = "SELECT appkey FROM appkeys;"
            cursor.execute(app_key_listing_sql)
            results = cursor.fetchall()
            app_keys = [  ]
            for result in results:
                app_keys.append( result[0] )
            return app_keys
        except Exception as e:
            print(f"An error occurred (list_all_app_keys): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (list_all_app_keys): {e}" )
            return [ ]    
        finally:
            if conn:
                conn.close()

    def get_user_permissions( self, username ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
                
            username = username.lower()
            conn = self.read_only_connection()
            cursor = conn.cursor()
            query_exists = "SELECT permissions FROM authentication WHERE username = ?"
            cursor.execute(query_exists, (username,))
            result = cursor.fetchone()
            if result is not None:
                return result[0]
            else:
                return None
        except Exception as e:
            print(f"An error occurred (get_user_permissions): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (get_user_permissions): {e}" )
            return None   
        finally:
            if conn:
                conn.close()

    # Increments the count of bad password attempts for the user.
    # Used for locking accounts on too many bad pass attempts
    # Doesn't lock admin accounts which are required to re-enable locked out users
    # If reset is True then resets the count to zero
    def increment_reset_bad_pass_attempts( self, username, reset = False ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
            username = username.lower()
            max_bad_pass_attempts = int( self.get_parameter_value( 'disable_account_after_bad_pass_attempts' ) )

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if reset:
                cursor.execute('UPDATE authentication SET bad_pass_attempts = 0 WHERE username = ?', (username,))
            else:
                cursor.execute('UPDATE authentication SET bad_pass_attempts = bad_pass_attempts + 1 WHERE username = ?', (username,))
                cursor.execute("UPDATE authentication SET disabled=TRUE WHERE bad_pass_attempts >= ? AND permissions != 'admin'", (max_bad_pass_attempts,))
            conn.commit()
        except Exception as e:
            print(f"An error occurred (increment_reset_bad_pass): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (increment_reset_bad_pass): {e}" )
            return False 
        finally:
            if conn:
                conn.close()    
            

    def set_pass( self, username, permissions, new_pass ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
            
            username = username.lower()
            
            if self.test_user_exists( username ):
                raise ValueError( "Error username being set already exists." )
            
            if not DBConfigHandler.validate_utf8_string( new_pass, max_length=DBConfigHandler.MAX_PASS_LENGTH ):
                raise ValueError( "Password is invalid" )
            
            if (not DBConfigHandler.validate_utf8_string(permissions)) or not (permissions in DBConfigHandler.VALID_PERMISSIONS):
                raise ValueError( "Invalid permissions" )
            
            pass_hash, salt = DBConfigHandler.make_bcrypt_pass( new_pass )
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM authentication WHERE username = ?', (username,) )
            query_insert_pass = 'INSERT INTO authentication ( username, permissions, pass_bcrypt, salt ) VALUES (?,?,?,?)'
            cursor.execute(query_insert_pass, (username, permissions, pass_hash,salt))
            conn.commit()
            self.insert_or_update_parameter( 'auth_state', 'string', 'authenticated' )
            return True      
        except Exception as e:
            print(f"An error occurred (set_pass): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (set_pass): {e}" )
            return False 
        finally:
            if conn:
                conn.close()

    def change_pass( self, username, new_pass ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
            
            username = username.lower()
            
            if not self.test_user_exists( username ):
                raise ValueError( "User for password change does not exist." )
            
            if not DBConfigHandler.validate_utf8_string( new_pass, max_length=DBConfigHandler.MAX_PASS_LENGTH ):
                raise ValueError( "Password is invalid" )
            
            pass_hash, salt = DBConfigHandler.make_bcrypt_pass( new_pass )
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            query_exists = "UPDATE authentication SET pass_bcrypt = ?, salt = ? WHERE username = ?"
            cursor.execute( query_exists, (pass_hash,salt,username) )
            conn.commit()
            return True      
        except Exception as e:
            print(f"An error occurred (change_pass): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (change_pass): {e}" )
            return False 
        finally:
            if conn:
                conn.close()


    def set_auth_token( self, response, username, session_id=None ):
        if DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
            username = username.lower()
            
            if session_id is None:
                session_id = str(uuid.uuid4()) 
            else:
                 if not DBConfigHandler.is_uuid_valid( session_id ):
                    raise ValueError( "session_id is invalid" )
            
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
            if not self.test_user_exists( username ):
                 raise ValueError( "Username does not exist" )
                    
            auth_token = secrets.token_hex(16)
            # Because we can decide what the token is and ensure it's long and random, we probably don't need to salt it or use bcrypt
            # We use sha512 here because it's considerably faster. Bcrypt takes about half a second on a Raspberry Pi.
            # We use bcrypt with salt for passwords because the user might enter a poor password that is short.
            hex_sha512_token = DBConfigHandler.sha512_hash( auth_token )
            self.store_new_auth_token( session_id, username, hex_sha512_token )
            
            max_cookie_session_age_s = int( self.get_parameter_value('max_session_age') ) * 86400
            
            response.set_cookie( 'auth_token', auth_token, max_age=max_cookie_session_age_s, httponly=True, secure=True, samesite='Strict' )
            response.set_cookie( 'session_id', session_id, max_age=max_cookie_session_age_s, httponly=True, secure=True, samesite='Strict' )
        else:
            raise ValueError( "Username is invalid" )

    def store_new_auth_token( self, session_id, username, token_sha512_hex ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
                
            if not self.test_user_exists( username ):
                 raise ValueError( "Username does not exist" )
                
            if not DBConfigHandler.is_uuid_valid( session_id ):
                raise ValueError( "session_id is invalid" )
            
            username = username.lower()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,) )
            insert_sql = 'INSERT INTO sessions ( session_id, username, token_sha512 ) VALUES (?,?,?)'
            cursor.execute(insert_sql, (session_id, username,token_sha512_hex ))
            conn.commit()
            return True          
        except Exception as e:
            print(f"An error occurred (store_new_auth_token): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (store_new_auth_token): {e}" )
            return False
        finally:
            if conn:
                conn.close()

    def remove_all_user_sessions( self, username ):
        conn = None
        try:
            if not DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                raise ValueError( "Username is invalid" )
            
            username = username.lower()
            
            # Don't test if user exists because this method is used to remove hanging sessions for deleted users
                
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            delete_sessions = "DELETE FROM sessions where username = ?"
            cursor.execute(delete_sessions, (username,) )
            conn.commit()
            return True          
        except Exception as e:
            print(f"An error occurred (remove_all_user_sessions): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (remove_all_user_sessions): {e}" )
            return False
        finally:
            if conn:
                conn.close()

    def remove_specific_user_session( self, session_id ):
        conn = None
        try:            
            if not DBConfigHandler.is_uuid_valid( session_id ):
                raise ValueError( "session_id is invalid" )            

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            delete_sessions = "DELETE FROM sessions WHERE session_id = ?"
            cursor.execute(delete_sessions, (session_id,) )
            conn.commit()
            return True          
        except Exception as e:
            print(f"An error occurred (remove_specific_user_sessions): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (remove_specific_user_sessions): {e}" )
            return False
        finally:
            if conn:
                conn.close()

    def expire_user_sessions( self ):
        conn = None
        try:            
            max_session_age_days = int( self.get_parameter_value('max_session_age') )
            if max_session_age_days is None or max_session_age_days < 1:
                raise ValueError('Bad session age parameter stored')
                
            expire_sessions_sql = "DELETE FROM sessions WHERE created_at < datetime('now', ?)"
            negative_days = str((max_session_age_days*-1))+' days'
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute( expire_sessions_sql, ( negative_days, ) )
            conn.commit()
            return True          
        except Exception as e:
            print(f"An error occurred (remove_specific_user_sessions): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (remove_specific_user_sessions): {e}" )
            return False
        finally:
            if conn:
                conn.close()

    def generate_app_key( self ):
            app_key = str(uuid.uuid4())
            secret = secrets.token_hex(16)
            hex_sha512_secret = DBConfigHandler.sha512_hash( secret )
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                insert_sql = 'INSERT INTO appkeys ( appkey, secret_sha512 ) VALUES ( ?, ? )'
                cursor.execute(insert_sql, (app_key, hex_sha512_secret ))
                conn.commit()
            except Exception as e:
                print(f"An error occurred (generate_app_key): {e}", file=sys.stderr)
                self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (generate_app_key): {e}" )
            finally:
                if conn:
                    conn.close()
            
            return( app_key, secret )
    
    
    def delete_app_key( self, app_key ):
            try:
                if not DBConfigHandler.is_uuid_valid( app_key ):
                    raise ValueError( "Invalid application key" )
            
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                delete_sql = 'DELETE FROM appkeys WHERE appkey = ?'
                cursor.execute(delete_sql, (app_key, ))
                conn.commit()
            except Exception as e:
                print(f"An error occurred (delete_app_key): {e}", file=sys.stderr)
                self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (delete_app_key): {e}" )
            finally:
                if conn:
                    conn.close()

    def get_app_keys( self ):
            try:
                conn = read_only_connection()
                cursor = conn.cursor()
                get_sql = 'SELECT appkey FROM appkeys ORDER BY created_at ASC'
                results = cursor.fetchall( get_sql )
                return results                
            except Exception as e:
                print(f"An error occurred (get_app_keys): {e}", file=sys.stderr)
                self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (get_app_keys): {e}" )
            finally:
                if conn:
                    conn.close()
            
            return( app_key, secret )


    def set_ip_allow_list( self, ip_white_list, ip_black_list):
        conn = None
        
        ip_white_list = [item.lower() for item in ip_white_list if isinstance(item, str)]
        ip_black_list = [item.lower() for item in ip_black_list if isinstance(item, str)]
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            delete_all = "DELETE FROM ip_allow_list;"
            cursor.execute(delete_all)
            set_ip_sql_whitelist = "INSERT INTO ip_allow_list ( ip, whitelisted ) VALUES (?, 1)"
            for ip in ip_white_list:
                if DBConfigHandler.is_valid_ipv4_or_ipv6_wildcard_range( ip ):
                    cursor.execute(set_ip_sql_whitelist, ( ip, ) )
            set_ip_sql_blacklist = "INSERT INTO ip_allow_list ( ip, whitelisted ) VALUES (?, 0)"
            for ip in ip_black_list:
                if DBConfigHandler.is_valid_ipv4_or_ipv6_wildcard_range( ip ):
                    cursor.execute(set_ip_sql_blacklist, ( ip, ) )
            conn.commit()
            self.ip_white_list = ip_white_list
            self.ip_black_list = ip_black_list
            return True
        except Exception as e:
            print(f"An error occurred (set_ip_allow_list): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (set_ip_allow_list): {e}" )
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()    
    
    def get_ip_allow_list( self ):
        conn = None
        ip_response = { 'whitelisted': [], 'blacklisted': [] }
        try:
            # Query to count the number of rows in the table
            conn = self.read_only_connection()
            query = "SELECT ip FROM ip_allow_list WHERE whitelisted = TRUE;"            
            cursor = conn.cursor()
            cursor.execute(query)
            whitelisted_ips = [row[0] for row in cursor.fetchall()]
            query = "SELECT ip FROM ip_allow_list WHERE whitelisted = FALSE;"            
            cursor.execute(query)
            blacklisted_ips = [row[0] for row in cursor.fetchall()]
            ip_response['whitelisted'] = whitelisted_ips
            ip_response['blacklisted'] = blacklisted_ips
        finally:
            if conn:
                conn.close()
        
        return ip_response

    def get_all_config( self, permissions ):      
        list_of_allowed_ips = self.get_ip_allow_list(  )
        
        config_data = {  }
        
        if permissions == 'admin':
            config_data = { 
                        'error': False, 
                        'allowed_ips': list_of_allowed_ips,
                        'enforce_ip_whitelist': self.get_parameter_value('enforce_ip_whitelist'),
                        'enforce_ip_blocklist': self.get_parameter_value('enforce_ip_blocklist'),
                        'usernames' : self.list_all_usernames(),
                        'app_keys' : self.list_all_app_keys(),
                        'image_rotation': self.get_parameter_value('image_rotation'),
                        'timestamp_scale': self.get_parameter_value('timestamp_scale_factor'),
                        'display_timestamp': self.get_parameter_value('display_timestamp'),
                        'timestamp_position': self.get_parameter_value('timestamp_position'),
                        'display_timestamp': self.get_parameter_value('display_timestamp')
                   }
            
        return config_data

    def validate_config_object( config_object ):
        if config_object:
            keys = [ 'allowed_ips', 'enforce_ip_whitelist', 'enforce_ip_blocklist', 'image_rotation', 'timestamp_position', 'display_timestamp' ]
            for key in keys:
                if key not in config_object:
                    return False
            if 'whitelisted' not in config_object['allowed_ips']:
                return False
            if 'blacklisted' not in config_object['allowed_ips']:
                return False
            if not isinstance(config_object['allowed_ips']['whitelisted'], list):
                return False
            if not isinstance(config_object['allowed_ips']['blacklisted'], list):
                return False
            if not isinstance(config_object['enforce_ip_whitelist'], bool):
                return False
            if not isinstance(config_object['enforce_ip_blocklist'], bool):
                return False
            if not isinstance( config_object['image_rotation'], int ):
                return False
            if config_object['image_rotation'] > 270 or config_object['image_rotation'] < 0 or (config_object['image_rotation'] % 90) != 0:
                return False
            if not isinstance( config_object['timestamp_position'], str ):
                return False
            if not isinstance( config_object['display_timestamp'], bool ):
                return False
            
            normalised_whitelisted = []
            for ip in config_object['allowed_ips']['whitelisted']:
                normalised_whitelisted.append( DBConfigHandler.expand_ipv6_with_wildcard( ip.strip().lower() ) )
            config_object['allowed_ips']['whitelisted'] = normalised_whitelisted
            
            normalise_blacklisted = []
            for ip in config_object['allowed_ips']['blacklisted']:
                normalise_blacklisted.append( DBConfigHandler.expand_ipv6_with_wildcard( ip.strip().lower() ) )
            config_object['allowed_ips']['blacklisted'] = normalise_blacklisted
            
            for ip in (config_object['allowed_ips']['whitelisted'] + config_object['allowed_ips']['blacklisted']):
                if not DBConfigHandler.is_valid_ipv4_or_ipv6_wildcard_range( ip ):
                    return False
            
            return True
        
        return False
    
    # Assumes validated input (use validate_config_object)
    def set_config( self, config_object ):
            with self.config_change_lock:
                if 'allowed_ips' in config_object:
                    self.set_ip_allow_list( config_object['allowed_ips']['whitelisted'], config_object['allowed_ips']['blacklisted'] )

                if 'enforce_ip_whitelist' in config_object:
                    self.insert_or_update_parameter( 'enforce_ip_whitelist', 'bool', config_object['enforce_ip_whitelist'] )
                    self.enforce_ip_whitelist = config_object['enforce_ip_whitelist']
                
                if 'enforce_ip_blocklist' in config_object:
                    self.insert_or_update_parameter( 'enforce_ip_blocklist', 'bool', config_object['enforce_ip_blocklist'] )
                    self.enforce_ip_blocklist = config_object['enforce_ip_blocklist']
                
                if 'image_rotation' in config_object:
                    self.insert_or_update_parameter( 'image_rotation', 'int', config_object['image_rotation'] )
                if 'display_timestamp' in config_object:
                    self.insert_or_update_parameter( 'display_timestamp', 'bool', config_object['display_timestamp'] )
                if 'timestamp_position' in config_object:
                    self.insert_or_update_parameter( 'timestamp_position', 'string' , config_object['timestamp_position'] )
                if 'timestamp_scale' in  config_object:
                    self.insert_or_update_parameter( 'timestamp_scale_factor', 'string' , config_object['timestamp_scale'] )
                if 'display_timestamp' in config_object:
                    self.insert_or_update_parameter( 'display_timestamp', 'bool' , config_object['display_timestamp'] )
    
    def validate_appkey_auth( self, appkey, secret ):
        try:                    
            if not DBConfigHandler.is_secret_valid( secret ):
                raise ValueError( "Secret received is invalid" )
                
            if not DBConfigHandler.is_uuid_valid( appkey ):
                raise ValueError( "Appkey received is invalid" )
                
            conn = self.read_only_connection()
            cursor = conn.cursor()
            
            query_exists = "SELECT secret_sha512 from appkeys WHERE appkey = ?"
            cursor.execute(query_exists, (appkey,))
            retrieved_secret_sha512 = cursor.fetchone()
            test_secret_sha512 = DBConfigHandler.sha512_hash( secret )
            if retrieved_secret_sha512:
                if len( retrieved_secret_sha512 ) == 1:
                    if retrieved_secret_sha512[0] == test_secret_sha512:
                        return True
                        
            return False
            
        except Exception as e:
            print(f"An error occurred (validate_appkey_auth): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (validate_appkey_auth): {e}" )
            return False
        finally:
            if conn:
                conn.close()

    def validate_token_auth( self, session_id, token_to_test ):
        conn = None
        
        try:                    
            if not DBConfigHandler.is_secret_valid( token_to_test ):
                raise ValueError( "Security token received is invalid" )
                
            if not DBConfigHandler.is_uuid_valid( session_id ):
                raise ValueError( "session_id received is invalid" )
            
            # Expire user sessions older than n days (per config)
            self.expire_user_sessions()

            conn = self.read_only_connection()
            cursor = conn.cursor()
            query_exists = "SELECT token_sha512, username from sessions WHERE session_id = ?"
            cursor.execute(query_exists, (session_id,))
            retrieved_token_sha512 = cursor.fetchone()
            test_token_sha512 = DBConfigHandler.sha512_hash( token_to_test )
            conn.close()
            conn = None
                        
            if retrieved_token_sha512:
                if len( retrieved_token_sha512 ) == 2:
                    if retrieved_token_sha512[0] == test_token_sha512:
                        username = retrieved_token_sha512[1].lower()
                        if self.test_user_exists( username ):
                            if not self.is_account_locked( username ):
                                return (True, username)
                            else:
                                self.remove_all_user_sessions( username )
                                return (False, None)    
                        else:
                            # User was deleted or something went wrong but still has a valid hanging login session
                            # If user doesn't exist then delete any remaining login sessions
                            self.remove_all_user_sessions( username )
                            return (False, None)
                        
            return (False, None)
        except Exception as e:
            print(f"An error occurred (validate_token_auth): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (validate_token_auth): {e}" )
            return (False, None)
        finally:
            if conn:
                conn.close()


    # Test if response is a uuid and exists in the challenge_response table (and if so deletes it)
    # This is to verify the authenticating user can genuinely receive data from us at their IP    
    def validate_challege(self, response):
        conn = None
        try:      
        
            self.expire_challenge_response()

            if not DBConfigHandler.is_secret_valid(response):
                raise ValueError( "Invalid challenge token" )

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # Check if the response exists
            query_exists = "SELECT EXISTS(SELECT 1 FROM challenge_response WHERE response = ?)"
            cursor.execute(query_exists, (response,))
            exists = cursor.fetchone()[0]

            if exists:
                # Delete the response since it exists
                query_delete = "DELETE FROM challenge_response WHERE response = ?"
                cursor.execute(query_delete, (response,))
                conn.commit()  # Commit the deletion
                conn.close()
                return True  # Item was found and deleted
            else:
                return False  # Item does not exist

        except Exception as e:
            print(f"An error occurred (validate_challege): {e}", file=sys.stderr)
            self.write_log_line( 'error', False, '', '', 'exception', f"An error occurred (validate_challege): {e}" )
            return None
        finally:
            if conn:
                conn.close()
    
