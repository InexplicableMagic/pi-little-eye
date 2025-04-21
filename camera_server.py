#!/usr/bin/env python3

from flask import Flask, Response, request, render_template, jsonify, make_response, send_from_directory, abort
from gevent import pywsgi
from pi_little_eye.db_config_handler import *
from pi_little_eye.camera_handler import *
from pi_little_eye.certificate_handler import *
import uuid
import argparse
import ssl

app = Flask(__name__)

# Return anti-caching headers to force the browser to check the live version of the REST URL
def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return no_cache

# Restrict the supplied post data to 16MB which should be plenty for all the REST methods
def limit_content_length(f):
    @wraps(f)
    def wrapper_function(*args, **kwargs):
        content_length = request.headers.get('Content-Length')
        if content_length and int(content_length) > 16*1024*1024:
            # Abort with a 413 if the content length is exceeded
            abort(413)
        return f(*args, **kwargs)
    return wrapper_function
    
# Suppress exeptions being printed to the terminal due to using the self-sign certificate usage
# These errors come up when the user is informed in the browser the cert is self-signed
# and the browser interrupts the connection
def suppress_bad_certificate_errors(context, type, value, tb):
    msg_lower = str(value).lower()
    if type is ssl.SSLError and (
        "sslv3 alert bad certificate" in msg_lower or
        "alert certificate unknown" in msg_lower or
        "eof occurred in violation of protocol" in msg_lower or 
        "http request" in msg_lower
    ):
        return  # Suppress error
    if type is ssl.SSLEOFError:
        return  # Suppress this error as well
        
    # Call the original handler for all other errors
    original_error_handler(context, type, value, tb)

def check_command_line_args(args, parser):
    if (args.certificate and not args.key) or (args.key and not args.certificate):
        parser.error('--certificate and --key must be used together.')        

# Look in the request and various headers for the client's IP address
# Might be multiple addresses if behind a proxy
def get_list_of_possible_client_ips():
    possible_client_ips = [  ]
    if DBConfigHandler.is_valid_ip_address( request.remote_addr ):
        possible_client_ips.append( request.remote_addr.lower().strip() )
    
    # List of untrusted headers that common proxies might add as the client IP
    # These are untrusted as they can be easily manipulated by the calling client
    # When whitelisting, all IPs found have to be on the whitelist to enable access. Any single blacklisted IP found will cause access to be denied.
    # So client manipulation of these headers is pointless as the only effect is the client could potentially lock themselves out. Changing the headers won't enable access.
    # However, it's worth checking as equally the client may not have the capability to modify the headers and an intervening proxy may set them with valid values.
    speculative_header_list = [ 'X-Forwarded', 'X-Real-IP', 'X-Client-IP', 'X-Cluster-Client-IP', 'True-Client-IP', 'CF-Connecting-IP', 'CF-Pseudo-IPv4' ]
    for header in speculative_header_list:
        untrusted_header_ip = request.headers.get(header, None)
        if untrusted_header_ip is not None:
            if isinstance(untrusted_header_ip, str):
                # Some headers comma separated multiple IPs such as X-Forwarded-For
                possible_untrusted_ip_list = untrusted_header_ip.split(',')
                for possible_untrusted_ip in possible_untrusted_ip_list:
                    possible_untrusted_ip = possible_untrusted_ip.lower().strip()
                    if DBConfigHandler.is_valid_ip_address( possible_untrusted_ip ):
                        possible_client_ips.append( possible_untrusted_ip )

    return possible_client_ips


def is_appkey_authenticated( appkey, secret ):
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        if not dbch.is_app_in_unathenticated_state():
            if dbch.validate_appkey_auth( appkey, secret ):
                return (True, "Authenticated", 200, appkey)
            else:
                return (False, "Bad appkey/secret", 401, None)
        else:
            return (False, "App in unauthenticated state", 401, None)
    else:
        return (False, "IP disallowed", 403, None)

def is_cookie_authenticated_with_challenge( challenge ):
    if dbch.validate_challege( challenge ):
        return is_cookie_authenticated()
    else:
        log_entry( 'warning', 'bad_challenge', f"Bad authentication attempt: incorrect challenge token received", alert=True )
        return(False, "Failed to validate challenge", 401, None)

def is_cookie_authenticated( ):
        if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
            session_id = request.cookies.get('session_id', None)
            auth_token = request.cookies.get('auth_token', None)
            
            if auth_token and session_id:
                if not dbch.is_app_in_unathenticated_state():
                        authenticated, username = dbch.validate_token_auth( session_id, auth_token )
                        if authenticated:
                            return (True, "Authenticated", 200, username.lower() )
                        else:
                            if username is None:
                                username = ''
                            log_entry( 'info', 'login_fail', f"Cookie authentication failure. Presented cookie not valid.", alert=False, username=username )
                            return (False, "Authentication failure", 401, None)
                else:
                    return (False, "App in unauthenticated state", 401, None)
            else:
                return (False, "No auth cookie sent", 401, None)
        else:
            log_entry( 'warning', 'ip_block', f"Authentication attempt from a disallowed IP", alert=True )
            return (False, "IP disallowed", 403, None)
            
        return(False, "Unknown error", 500, None)

def log_entry( level, log_type, message, alert = False, ip_route=None, username=None ):
    ip_route = ','.join( get_list_of_possible_client_ips() )
    dbch.write_log_line( level, alert, username, ip_route, log_type, message )

@app.route('/api/v1/video/mjpeg', methods=['GET'])
@nocache
def video_mjpeg():
    authenticated = False
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        appkey = request.args.get('appkey', None)
        secret = request.args.get('secret', None)
        if DBConfigHandler.is_uuid_valid( appkey ) and DBConfigHandler.is_secret_valid( secret ):
            (authenticated, message, http_code, username) = is_appkey_authenticated(appkey,secret)        
        else:
            (authenticated, message, http_code, username) = is_cookie_authenticated( )
        
        if not authenticated:
            # If authentication has failed, return a blank image with a message
            # This response will be going to an HTML img element which won't see any text
            return Response(CameraHandler.create_message_image(message),mimetype='image/png')
        else:
            try:
                if not ch.is_camera_detected():
                    return Response(CameraHandler.create_message_image("No camera detected"),mimetype='image/png')

                # If authentication was successful, return the video feed
                log_entry( 'info', 'video_viewed', f"Camera viewed", username=username )
                return Response(ch.generate_camera_video(username), mimetype='multipart/x-mixed-replace; boundary=frame')
            except RuntimeError as e:
                return Response(CameraHandler.create_message_image("Camera Failure (see logs)"),mimetype='image/png')
            except Exception as e:
                return Response(CameraHandler.create_message_image("Camera Exception (see logs)"),mimetype='image/png')
    else:
         return Response(CameraHandler.create_message_image("IP disallowed"),mimetype='image/png')

@app.route('/api/v1/test-auth-state', methods=['POST'])
@limit_content_length
@nocache
def test_auth_state():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        post_data = request.get_json(silent=True)
        session_id = request.cookies.get('session_id', None)
        
        authenticated = False        
        
        if post_data:
            challenge = post_data.get('challenge', None)
            if challenge:
                (authenticated, message, http_code, username) = is_cookie_authenticated_with_challenge( challenge )
                if authenticated:
                    user_permissions = dbch.get_user_permissions( username )
                    if user_permissions:
                        response = make_response( jsonify(  { 'auth_state': 'authenticated', 'permissions': user_permissions } ), 200 )
                    else:
                        response = make_response( jsonify(  { 'error': True, 'message': 'Failure getting permissions for user' } ), 500 )
                elif dbch.is_app_in_unathenticated_state():            
                    response = make_response( jsonify(  { 'auth_state': 'set_initial_password' } ), 200 )
                else:
                    response = make_response( jsonify(  { 'auth_state': 'login_required' } ), 200 )
                    response.delete_cookie('session_id')
                    response.delete_cookie('auth_token')
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'Challenge parameter not set in POST data.' } ), 400 )
    else:
        # IP Blocked   
        response = make_response( jsonify( {'auth_state': 'access_denied'} ), 200 )

    return response

# Logout the current user, or an admin can logout a different user
@app.route('/api/v1/logout', methods=['POST'] )
@limit_content_length
@nocache
def logout():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    
    (authenticated, message, http_code, this_user_username) = is_cookie_authenticated( )
    if not authenticated:
        return make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        logout_this_user = True    
        post_data = request.get_json(silent=True)
        if post_data:
            user_to_logout = post_data.get('username', None)
            if user_to_logout is not None:
                user_to_logout = user_to_logout.lower()
                if user_to_logout != this_user_username:
                    current_user_permissions = dbch.get_user_permissions( this_user_username )
                    if current_user_permissions == 'admin':
                        dbch.remove_all_user_sessions( user_to_logout )
                        ch.logout_user( user_to_logout )
                        logout_this_user = False
                        log_entry( 'info', 'logout', f"Admin logged out user \"{user_to_logout}\"", username=this_user_username )
                        response = make_response( jsonify(  { 'error': False, 'message': 'User logged out' } ), 200 )
                    else:
                        response = make_response( jsonify(  { 'error': True, 'message': 'Not authorised to logout other users' } ), 403 )
                        
        if logout_this_user:
            dbch.remove_all_user_sessions( this_user_username )
            ch.logout_user( this_user_username )
            log_entry( 'info', 'logout', f"Logged out", username=this_user_username )
            response = make_response( jsonify (  { 'error': False, 'message': 'logged out' } ), 200 )
            response.delete_cookie('session_id')
            response.delete_cookie('auth_token')
            return response
        
    return response 

@app.route('/api/v1/get-config' )
@nocache
def get_config():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username) = is_cookie_authenticated( )
    if not authenticated:
        return make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        current_user_permissions = dbch.get_user_permissions( username )
        # Add config that comes from the database settings
        config = dbch.get_all_config( current_user_permissions )
        #Add config based on the current camera state
        config = ch.append_camera_current_config( config )
        config['current_username'] = username
        return make_response( jsonify ( config ), 200 )
        
    return response
    
@app.route('/api/v1/set-config', methods=['POST'] )
@limit_content_length
@nocache
def set_config():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username) = is_cookie_authenticated( )
    
    if not authenticated:
        return make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        post_data = request.get_json(silent=True)
        if post_data:
            csrf_in_post = post_data.get('csrf_token', None)
            csrf_in_cookie = request.cookies.get('csrf_token')
            if DBConfigHandler.is_uuid_valid( csrf_in_cookie ) and DBConfigHandler.is_uuid_valid( csrf_in_post ) and csrf_in_cookie == csrf_in_post:
                current_user_permissions = dbch.get_user_permissions( username )
                if current_user_permissions is not None and current_user_permissions == 'admin':
                    if DBConfigHandler.validate_config_object( post_data ):
                        # Set options to be stored in the config - config must be validated
                        dbch.set_config( post_data )
                        # Set options that change the camera state
                        ch.set_config( post_data )
                        log_entry( 'info', 'config_change', "Modified configuration", alert=False, username=username )
                        response = make_response( jsonify ( { 'error': False, 'message': 'Config set' } ), 200 )
                    else:
                        response = make_response( jsonify ( { 'error': True, 'message': 'Config validation error' } ), 400 )
                else:
                    response = make_response( jsonify ( { 'error': True, 'message': 'Only admin user can set the config' } ), 403 )
            else:
                log_entry( 'warning', 'csrf', f"Anti cross-site script check failure when setting config. Might be a browser cookie problem but could indicate a possible malicious link click.", alert=True )
                response = make_response( jsonify ( { 'error': True, 'message': 'CSRF problem', 'err_type': 'csrf_problem' } ), 400 )
    
    return response

@app.route('/api/v1/get-logs', methods=['GET'])
@nocache
def get_logs():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username) = is_cookie_authenticated( )
    if not authenticated:
        response =  make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        current_user_permissions = dbch.get_user_permissions( username )
        if current_user_permissions == 'admin':
                page_size = 100
                from_line = request.args.get('from', None)
                (logs, min_id, max_id) = dbch.get_logs_paged( from_line=from_line, page_size=page_size )
                page_start = -1
                page_end = -1
                if len(logs) > 0:
                    page_start = logs[0][0]
                    page_end = logs[-1][0]
                
                response = make_response( jsonify ( {   'error': False, 
                                                        'message': '', 
                                                        'min_id': min_id,           #Minimum ID available in the logs (earliest log line)
                                                        'max_id': max_id,           #Maximum ID available in the logs (latest log line)
                                                        'page_start': page_start,   #The start ID of the specific page of logs returned (largest ID)
                                                        'page_end': page_end,       #The end ID of the specific page of logs returned (smallest ID)
                                                        'page_size': page_size,     #The page size
                                                        'logs': logs } ), 200 ) 
        else:
            response = make_response( jsonify ( { 'error': True, 'message': 'Only admin user can see the logs' } ), 403 )
        
    return response

@app.route('/api/v1/log-management', methods=['POST'])
@limit_content_length
@nocache  
def log_management():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username) = is_cookie_authenticated( )
    if not authenticated:
        response =  make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        current_user_permissions = dbch.get_user_permissions( username )
        if current_user_permissions == 'admin':
            post_data = request.get_json(silent=True)
            if post_data:
                csrf_in_post = post_data.get('csrf_token', None)
                csrf_in_cookie = request.cookies.get('csrf_token')
                if DBConfigHandler.is_uuid_valid( csrf_in_cookie ) and DBConfigHandler.is_uuid_valid( csrf_in_post ) and csrf_in_cookie == csrf_in_post:
                    if 'full_clear' in post_data and post_data['full_clear']:
                        dbch.delete_old_log_lines( full_clear = True )
                        log_entry( 'info', 'logs_cleared', f"Cleared logs", username=username )
                        response = make_response( jsonify ( { 'error': False, 'message': 'Logs cleared' } ), 200 )
                else:
                    response = make_response( jsonify ( { 'error': True, 'message': 'CSRF parameter or cookie problem. Try refreshing page.', 'err_type': 'csrf_problem' } ), 400 )
                    log_entry( 'warning', 'csrf', f"Anti cross-site script check failure when managing logs. Might be a browser cookie problem but could indicate a possible malicious link click.", alert=True )       
        else:
            response = make_response( jsonify ( { 'error': True, 'message': 'Only admin user can manage the logs' } ), 403 )
        
    return response

   
# Lock/unlock or delete a user account
@app.route('/api/v1/account-management', methods=['POST'] )
@limit_content_length
@nocache
def account_management():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username_authenticated) = is_cookie_authenticated( )
    
    if not authenticated:
        return make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        post_data = request.get_json(silent=True)
        if post_data:
            csrf_in_post = post_data.get('csrf_token', None)
            csrf_in_cookie = request.cookies.get('csrf_token')
            if DBConfigHandler.is_uuid_valid( csrf_in_cookie ) and DBConfigHandler.is_uuid_valid( csrf_in_post ) and csrf_in_cookie == csrf_in_post:
                if dbch.test_user_exists( username_authenticated ): 
                    current_user_permissions = dbch.get_user_permissions( username_authenticated )
                    if current_user_permissions is not None and current_user_permissions == 'admin':
                        username_postdata = post_data.get('username', None)
                        action = post_data.get('action', None)
                        if username_postdata and action:                  
                            if dbch.test_user_exists( username_postdata ):
                                if username_authenticated.lower() != username_postdata.lower():
                                    if action == 'lock':
                                        dbch.lock_unlock_delete_account( username_postdata, 'lock' )
                                        dbch.remove_all_user_sessions( username_postdata )
                                        ch.logout_user( username_postdata )
                                        log_entry( 'info', 'account_locked', f"Account \"{username_postdata}\" locked", username=username_authenticated )
                                        response = make_response( jsonify ( { 'error': False, 'message': 'Account locked' } ), 200 )
                                    elif action == 'unlock':
                                        dbch.lock_unlock_delete_account( username_postdata, 'unlock' )
                                        log_entry( 'info', 'account_unlocked', f"Account \"{username_postdata}\" unlocked", username=username_authenticated )
                                        response = make_response( jsonify ( { 'error': False, 'message': 'Account unlocked' } ), 200 )
                                    elif action == 'delete':
                                        dbch.lock_unlock_delete_account( username_postdata, 'delete' )
                                        dbch.remove_all_user_sessions( username_postdata )
                                        ch.logout_user( username_postdata )
                                        log_entry( 'info', 'account_deleted', f"Account \"{username_postdata}\" deleted", username=username_authenticated )
                                        response = make_response( jsonify ( { 'error': False, 'message': 'Account deleted' } ), 200 )
                                    else:
                                        response = make_response( jsonify ( { 'error': True, 'message': 'Incorrect action. Must be unlock,lock or delete', 'err_type': 'bad_action' } ), 400 )        
                                else:
                                    response = make_response( jsonify ( { 'error': True, 'message': 'Cant lock/unlock or delete own account.', 'err_type': 'username_missing' } ), 403 )
                            else:
                                log_entry( 'warning', 'admin', f"Attempted to perform account management on non-existent account", alert=True, username=username_authenticated )
                                response = make_response( jsonify ( { 'error': True, 'message': 'username doesnt exist', 'err_type': 'user_not_exists' } ), 400 )
                        else:
                            response = make_response( jsonify ( { 'error': True, 'message': 'Username missing in post data', 'err_type': 'username_missing' } ), 400 )
                    else:
                        log_entry( 'warning', 'admin', f"Attempted to perform account management but not an admin", alert=True, username=username_authenticated )
                        response = make_response( jsonify ( { 'error': True, 'message': 'Only admin account can perform this operation', 'err_type': 'needs_admin' } ), 403 )
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'CSRF parameter or cookie problem. Try refreshing page.', 'err_type': 'csrf_problem' } ), 400 )
                log_entry( 'warning', 'csrf', f"Anti cross-site script check failure in account management. Might be a browser cookie problem but could indicate a possible malicious link click.", alert=True )
    
    return response
    
@app.route('/api/v1/get-challenge')
@nocache
def get_challenge():
    #TODO: anti-hammer
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        return make_response( jsonify( { 'error': False, 'message':'', 'challenge' : dbch.generate_challenge_response( ) } ), 200 )
    else:
        log_entry( 'warning', 'ip_block', f"Attempt to retrieve challenge token from blocked IP", alert=True )
        return make_response( jsonify( { 'error': True, 'message':'IP disallowed' } ), 403)
        

@app.route('/api/v1/login', methods=['POST'] )
@limit_content_length
@nocache
def login():
    response = make_response( jsonify( { 'error': True, 'message': 'unknown error' } ), 500 )
    
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        post_data = request.get_json(silent=True)
        if post_data:
            username = post_data.get('username', None)
            password = post_data.get('password', None)
            challenge = post_data.get('challenge', None)
            if username and password and challenge:
                if DBConfigHandler.validate_utf8_string( username, max_length=DBConfigHandler.MAX_USERNAME_LENGTH ):
                    if DBConfigHandler.validate_utf8_string( password, max_length=DBConfigHandler.MAX_PASS_LENGTH ):
                        if dbch.validate_challege( challenge ):
                            if dbch.verify_password( username, password ):
                                #Password check passed
                                #If the user is already correctly authenticated with an existing session then log the current session out before switching to a new one
                                (authenticated, message, http_code, username_authenticated) = is_cookie_authenticated( )
                                if authenticated:
                                    session_id = request.cookies.get('session_id', None)
                                    dbch.remove_specific_user_session( session_id )
                                
                                response = make_response( jsonify ( { 'error': False, 'pass_OK': True, 'message': 'Login successful.' } ), 200 )
                                dbch.set_auth_token( response, username )
                                log_entry( 'info', 'login_success', f"Logged in", username=username )
                            else:
                                response = make_response( jsonify ( { 'error': True, 'pass_OK': False, 'message': 'Login failed with supplied username/pass.' } ), 401 )
                                log_entry( 'warning', 'login_fail', f"Login failure with username: \"{username}\". Bad user or pass.", alert=True )
                        else:
                            response = make_response( jsonify ( { 'error': True, 'message': 'Bad challenge received.' } ), 400 )
                            log_entry( 'warning', 'bad_challenge', f"Bad login attempt: incorrect challenge token received", alert=True, username=username )
                    else:
                        log_entry( 'warning', 'login_fail', f"Login attempt with incorrect password format.", alert=True, username=username )
                        response = make_response( jsonify ( { 'error': True, 'message': 'Invalid password format' } ), 400 )    
                else:
                    response = make_response( jsonify ( { 'error': True, 'message': 'Invalid username format' } ), 400 )
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'username,password or challenge parameters must be set in POST request.' } ), 400 )
    else:
        response = make_response( jsonify( { 'error': True, 'message': 'IP disallowed' } ), 403 )
        log_entry( 'warning', 'ip_block', f"Attempted login from blocked IP", alert=True )
    
    return response

@app.route('/api/v1/set-pass', methods=['POST'] )
@limit_content_length
@nocache
def set_pass():
    response = make_response( jsonify( { 'error': True, 'message': 'unknown error', 'err_type': 'other' } ), 500 ) 
    
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        post_data = request.get_json(silent=True)
        
        if post_data:
            username_postdata = post_data.get('username', None)
            new_password = post_data.get('new_password', None)
            # Not required when setting the initial password for the app
            original_password = post_data.get('original_password', None)
            #The "challenge" value can be obtained from the /get_challenge method
            challenge = post_data.get('challenge', None)
            csrf_in_post = post_data.get('csrf_token', None)
            csrf_in_cookie = request.cookies.get('csrf_token')
            
            if DBConfigHandler.is_uuid_valid( csrf_in_cookie ) and DBConfigHandler.is_uuid_valid( csrf_in_post ) and csrf_in_cookie == csrf_in_post:        
                if new_password and challenge:
                    if dbch.validate_challege( challenge ):
                        # Check if the app is waiting for the initial admin password to be set
                        if dbch.is_app_in_unathenticated_state():
                            if username_postdata:
                                if dbch.set_pass( username_postdata, 'admin', new_password ):
                                    log_entry( 'info', 'password_set', f"Initial admin password set", username=username_postdata )
                                    response = make_response( jsonify( { 'error': False, 'message': 'Password set.' } ), 200 )
                                else:
                                    response = make_response( jsonify( { 'error': True, 'message': 'Failed to set password.' } ), 500 )
                        else:
                            # An initial admin password has been set - so check the user is authenticated before allowing a password change
                            (authenticated, message, http_code, username_authenticated) = is_cookie_authenticated( )
                            if not authenticated:
                                log_entry( 'warning', 'auth_failure', f"Authentication failure attempting to set password for user \"{username_postdata}\"", alert=True )
                                return make_response( jsonify ( { 'error': True, 'message': message, 'err_type': 'auth_failure' } ), http_code )
                            else:
                                # We have just tested the user can correctly authenticate with this username
                                
                                # If the user is trying to change their own password and they can verify their original password
                                if not username_postdata:
                                    if original_password:
                                        if dbch.verify_password( username_authenticated, original_password ):
                                            dbch.change_pass( username_authenticated, new_password )
                                            response = make_response( jsonify( { 'error': False, 'message': 'Password changed.' } ), 200 )
                                            log_entry( 'info', 'password_set', f"Changed password", username=username_authenticated )
                                        else:
                                            response = make_response( jsonify ( { 'error': True, 'message': 'Original password incorrect', 'err_type': 'oiginal_pass_failure' } ), 401 )
                                            log_entry( 'warning', 'password_failure', f"Tried to change password but entered incorrect original password", username=username_authenticated, alert=True )
                                    else:
                                        response = make_response( jsonify ( { 'error': True, 'message': 'Original password not set', 'err_type': 'pass_not_set' } ), 400 )
                                else:
                                    # The user is trying to set someone else's password, in which case they need to be an admin
                                    current_user_permissions = dbch.get_user_permissions( username_authenticated )
                                    if current_user_permissions is not None:     
                                        if username_postdata:
                                            # The user has admin permission and is not trying to change their own password
                                            if current_user_permissions == 'admin':
                                                if username_authenticated != username_postdata:
                                                    # Allow the change if the user has authenticated as an admin
                                                    if not dbch.test_user_exists( username_postdata ):
                                                        account_type_postdata = post_data.get('account_type', 'viewer')
                                                        if account_type_postdata in ['admin', 'viewer']:
                                                            if dbch.set_pass( username_postdata, account_type_postdata, new_password ):
                                                                response = make_response( jsonify( { 'error': False, 'message': 'Password set.' } ), 200 )
                                                                log_entry( 'info', 'password_set', f"Added new account \"{username_postdata}\" of type \"{account_type_postdata}\"", username=username_authenticated )
                                                                
                                                            else:
                                                                response = make_response( jsonify( { 'error': False, 'message': 'Failed to set password.' } ), 500 )
                                                        else:
                                                            response = make_response( jsonify( { 'error': True, 'message': 'Error, account type must be admin or viewer.','err_type': 'wrong_account_type' } ), 400 )    
                                                    else:
                                                        response = make_response( jsonify( { 'error': True, 'message': 'Error, user already exists','err_type': 'user_exists' } ), 400 )
                                                else:
                                                    response = make_response( jsonify( { 'error': True, 'message': 'Error, cant set own user pass','err_type': 'no_set_own_user' } ), 400 )
                                            else:
                                                log_entry( 'warning', 'password_failure', f"Tried to change password for user \"{username_postdata}\" via the API but denied as not admin.", username=username_authenticated, alert=True )
                                                response = make_response( jsonify ( { 'error': True, 'message': 'Not authorized to set password for a different user', 'err_type': 'bad_group' } ), 403 )                    
                            
                    else:
                        response = make_response( jsonify ( { 'error': True, 'message': 'Bad challenge received.', 'err_type': 'bad_challenge' } ), 400 )
                        log_entry( 'warning', 'bad_challenge', f"Challenge token failure on trying to set password.", alert=True )
                else:
                    response = make_response( jsonify ( { 'error': True, 'message': 'username,new-password and challenge parameters must be set in POST request.', 'err_type': 'bad_post' } ), 400 )
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'CSRF parameter or cookie problem. Try refreshing page.', 'err_type': 'csrf_problem' } ), 400 )
                log_entry( 'warning', 'csrf', f"Anti cross-site script check failure on trying to set password. Might be a browser cookie problem but could indicate a possible malicious link click.", alert=True )
        else:
            response = make_response( jsonify ( { 'error': True, 'message': 'JSON parse error', 'err_type': 'json_parse' } ), 400 )
    else:
        response = make_response( jsonify( { 'error': True, 'message': 'IP disallowed', 'err_type': 'ip_block' } ), 403 )
        log_entry( 'warning', 'ip_block', f"Attempt to set password by blocked IP", alert=True )
    
    return response

@app.route('/api/v1/generate-app-key', methods=['POST'] )
@limit_content_length
@nocache
def generate_app_key():
    response = make_response( jsonify( { 'error': True, 'message': 'unknown error', 'err_type': 'other' } ), 500 )
    post_data = request.get_json(silent=True)
    if post_data:
        challenge = post_data.get('challenge', None)
        csrf_in_post = post_data.get('csrf_token', None)
        csrf_in_cookie = request.cookies.get('csrf_token')
        if DBConfigHandler.is_uuid_valid( csrf_in_cookie ) and DBConfigHandler.is_uuid_valid( csrf_in_post ) and csrf_in_cookie == csrf_in_post:
            (authenticated, message, http_code, username_authenticated) = is_cookie_authenticated_with_challenge( challenge )
            if authenticated:
                current_user_permissions = dbch.get_user_permissions( username_authenticated )
                if current_user_permissions == 'admin':
                    ( appkey, secret ) = dbch.generate_app_key( )
                    log_entry( 'info', 'appkey', f"Generated new app key {appkey}", username=username_authenticated )
                    response = make_response( jsonify ( { 'error': False, 'message': '', 'appkey': appkey, 'secret': secret } ), 200 )
                else:
                    log_entry( 'warning', 'admin', f"Attempted to generate an app key when not admin", username=username_authenticated, alert=True )
                    response = make_response( jsonify ( { 'error': True, 'message': 'Only admin account can perform this operation', 'err_type': 'needs_admin' } ), 403 )
            else:
                # Shouldn't be able to perform this action unless already logged in
                log_entry( 'warning', 'admin', "Unexpected authentication failure when attempting to generate app key", alert=True )
                return make_response( jsonify ( { 'error': True, 'message': message, 'err_type': 'auth_failure' } ), http_code )
        else:
            log_entry( 'warning', 'csrf', f"Anti cross-site script check failure on trying to generate appkey. Might be a browser cookie problem but could indicate a possible malicious link click.", alert=True )
            response = make_response( jsonify ( { 'error': True, 'message': 'CSRF parameter or cookie problem when generating an app key. Try refreshing page.', 'err_type': 'csrf_problem' } ), 400 )               
    
    return response

@app.route('/api/v1/delete-app-key', methods=['POST'] )
@limit_content_length
@nocache
def delete_app_key():
    response = make_response( jsonify( { 'error': True, 'message': 'unknown error', 'err_type': 'other' } ), 500 )
    post_data = request.get_json(silent=True)
    if post_data:
        csrf_in_post = post_data.get('csrf_token', None)
        csrf_in_cookie = request.cookies.get('csrf_token')
        if DBConfigHandler.is_uuid_valid( csrf_in_cookie ) and DBConfigHandler.is_uuid_valid( csrf_in_post ) and csrf_in_cookie == csrf_in_post:
            (authenticated, message, http_code, username_authenticated) = is_cookie_authenticated( )
            if authenticated:
                current_user_permissions = dbch.get_user_permissions( username_authenticated )
                if current_user_permissions == 'admin':
                        app_key_to_delete = post_data.get('app_key', None)
                        log_entry( 'info', 'appkey', f"Deleted app key {app_key_to_delete}", username=username_authenticated )
                        ch.logout_user( app_key_to_delete )
                        dbch.delete_app_key( app_key_to_delete )
                        response = make_response( jsonify ( { 'error': False, 'message': 'App key deleted' } ), 200 )
                else:
                    log_entry( 'warning', 'admin', f"Attempted to delete an app key when not admin", username=username_authenticated, alert=True )
                    response = make_response( jsonify ( { 'error': True, 'message': 'Only admin account can delete an app key', 'err_type': 'needs_admin' } ), 403 )
            else:
                # Shouldn't be able to perform this action unless already logged in
                log_entry( 'warning', 'admin', "Unexpected authentication failure when attempting to delete app key", alert=True )
                return make_response( jsonify ( { 'error': True, 'message': message, 'err_type': 'auth_failure' } ), http_code )
        else:
            log_entry( 'warning', 'csrf', f"Anti cross-site script check failure on trying to delete appkey. Might be a browser cookie problem but could indicate a possible malicious link click.", alert=True )
            response = make_response( jsonify ( { 'error': True, 'message': 'CSRF parameter or cookie problem on deleting an app key. Try refreshing page.', 'err_type': 'csrf_problem' } ), 400 )               
    
    return response


@app.route('/robots.txt')
def static_from_root():
    log_entry( 'warning', 'robots', 'robots.txt file was requested. This may indicate a web search engine has discovered this camera.', alert=True )
    return send_from_directory(app.static_folder, request.path[1:])
    

@app.route('/')
@nocache
def index():
    csrf_token = request.cookies.get('csrf_token')

    if not csrf_token:
        # If no token exists, generate a new one
        csrf_token = str(uuid.uuid4())

    response = make_response(render_template('index.html', csrf_token=csrf_token))
    if 'csrf_token' not in request.cookies:
        response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    log_entry( 'info', 'index_page', 'Front page accessed' )
    return response


if __name__ == '__main__':
        
    parser = argparse.ArgumentParser(description="Raspberry Pi Security Camera")
    # Add the arguments
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host address to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5220, help='Port number to bind to (default: 5220)')
    parser.add_argument('--certificate', type=str, help='Optionally supply a path to your own PEM format TLS certificate (self-sign auto-generated by default)')
    parser.add_argument('--key', type=str, help='Path to the private key in PEM associated with the supplied certificate')
    parser.add_argument('--disable-ip-lists', action='store_true', help='Disable IP white list and block list - use if you have accidentally blocked your own IP')
    parser.add_argument('--factory-reset', action='store_true', help='Reset to factory defaults - use e.g. if you have forgotten the admin password')

    # Parse the arguments
    args = parser.parse_args()
    check_command_line_args( args, parser )
    
    dbch = DBConfigHandler("security_cam_state.sqlite", args.factory_reset)
    ch = CameraHandler( dbch )
    dbch.write_log_line( 'info', False, '','', 'software_started', 'Software started' )
        
    # Option to enable access if the user has locked themselves out due to incorrect IP whitelist settings
    if args.disable_ip_lists:
        self.write_log_line( 'warning', True, '','', 'ip_disable', 'IP whitelist/blocklist disabled via command line' )
        dbch.disable_ip_whitelist_and_blocklist()
    
    # Suppress exceptions caused by self-sign certificate usage being printed to the terminal
    original_error_handler = gevent.get_hub().handle_error
    gevent.get_hub().handle_error = suppress_bad_certificate_errors
    
    # User supplies their own certificate option
    if args.certificate and args.key:
        # User supplied certificate and key
        keyfile = args.key
        certfile = args.certificate
    else:
        # Generate a self-sign TLS certificate by default so the user doesn't have to supply one   
        CertificateHandler.update_tls_certificates()
        keyfile = CertificateHandler.get_key_file_path()
        certfile = CertificateHandler.get_cert_file_path()

    http_server = pywsgi.WSGIServer( (args.host, args.port), app, keyfile=keyfile, certfile=certfile )
    http_server.serve_forever()

