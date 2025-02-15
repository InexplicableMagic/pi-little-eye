#!/usr/bin/env python3

from flask import Flask, Response, request, render_template, jsonify, make_response, send_from_directory
from waitress import serve
from db_config_handler import *
from camera_handler import *
import uuid

app = Flask(__name__)

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return no_cache

def is_authenticated_with_challenge( challenge ):
    if dbch.validate_challege( challenge ):
        return is_authenticated()
    else:
        return(False, "Failed to validate challenge", 401, None)
    
def get_list_of_possible_client_ips():
    possible_client_ips = [  ]
    if DBConfigHandler.is_valid_ip_address( request.remote_addr ):
        possible_client_ips.append( request.remote_addr.lower().strip() )
    # List of headers that proxies might add as the client IP
    # These are untrusted as might be manipulated by the calling client
    # However, it's worth checking as equally the client may not be able to modify them
    speculative_header_list = [ 'HTTP_X_FORWARDED_FOR', 'X-Real-IP', 'CF-Connecting-IP', 'CF-Pseudo-IPv4' ]
    for header in speculative_header_list:
        untrusted_header_ip = request.environ.get(header, None)
        if untrusted_header_ip is not None:
            if DBConfigHandler.is_valid_ip_address( untrusted_header_ip ):
                possible_client_ips.append( untrusted_header_ip.lower().strip() )
    return possible_client_ips


def is_authenticated( ):
        if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
            session_id = request.cookies.get('session_id', None)
            auth_token = request.cookies.get('auth_token', None)
            
            if auth_token and session_id:
                if not dbch.is_app_in_unathenticated_state():
                        authenticated, username = dbch.validate_token_auth( session_id, auth_token )
                        if authenticated:
                            return (True, "Authenticated", 200, username)
                        else:
                            return (False, "Authentication failure", 401, None)
                else:
                    return (False, "App in unauthenticated state", 401, None)
            else:
                return (False, "No auth cookie sent", 400, None)
        else:
            return (False, "IP disallowed", 401, None)
            
        return(False, "Unknown error", 500, None)

@app.route('/api/v1/video_feed', methods=['GET'])
@nocache
def video_feed():
    authenticated = False
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        try:
            challenge = request.args.get('challenge', None)
            if challenge is None or (not DBConfigHandler.is_uuid_valid(challenge)):
                return Response(CameraHandler.create_message_image("No challenge set"),mimetype='image/png')
            
            (authenticated, message, http_code, username) = is_authenticated_with_challenge( challenge )
            
        except Exception as e:
            return Response(CameraHandler.create_message_image("Failure validating challenge"),mimetype='image/png')
        
        if not authenticated:
            # If authentication has failed, return a blank image with a message
            # This response will be going to an HTML img element which won't see any text
            return Response(CameraHandler.create_message_image(message),mimetype='image/png')
        else:
            try:
                # If authentication was successful, return the video feed
                return Response(ch.generate_camera_video(username), mimetype='multipart/x-mixed-replace; boundary=frame')
            except RuntimeError as e:
                return Response(CameraHandler.create_message_image("Camera Failure (see logs)"),mimetype='image/png')
            except Exception as e:
                return Response(CameraHandler.create_message_image("Camera Exception (see logs)"),mimetype='image/png')
    else:
         return Response(CameraHandler.create_message_image("IP disallowed"),mimetype='image/png')

@app.route('/api/v1/test_auth_state', methods=['POST'])
@nocache
def auth_state():
    #TODO: Verify IP Allowed
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        post_data = request.get_json(silent=True)
        session_id = request.cookies.get('session_id', None)
        
        authenticated = False        
        
        if post_data:
            challenge = post_data.get('challenge', None)
            if challenge:
                (authenticated, message, http_code, username) = is_authenticated_with_challenge( challenge )
                if authenticated:
                    user_permissions = dbch.get_user_permissions( username )
                    if user_permissions:
                        response = make_response( jsonify(  { 'auth-state': 'authenticated', 'permissions': user_permissions } ), 200 )
                    else:
                        response = make_response( jsonify(  { 'error': True, 'message': 'Failure getting permissions for user' } ), 500 )
                elif dbch.is_app_in_unathenticated_state():            
                    response = make_response( jsonify(  { 'auth-state': 'set_initial_password' } ), 200 )
                else:
                    response = make_response( jsonify(  { 'auth-state': 'login_required' } ), 200 )
                    response.delete_cookie('session_id')
                    response.delete_cookie('auth_token')
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'Challenge parameter not set in POST data.' } ), 400 )
    else:
         response = make_response( jsonify( {'auth-state': 'ip_banned'} ), 200 )

    return response

@app.route('/api/v1/logout' )
@nocache
def logout():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username) = is_authenticated( )
    if not authenticated:
        return make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        dbch.remove_all_user_sessions( username )
        ch.logout_user( username )
        response = make_response( jsonify (  { 'error': False, 'message': 'logged out' } ), 200 )
        response.delete_cookie('session_id')
        response.delete_cookie('auth_token')
        return response
        
    return response 

@app.route('/api/v1/get_config' )
@nocache
def get_config():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username) = is_authenticated( )
    if not authenticated:
        return make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        config = dbch.get_all_config()
        return make_response( jsonify ( config ), 200 )
        
    return response 
    
@app.route('/api/v1/set_config', methods=['POST'] )
@nocache
def set_config():
    response = make_response( jsonify(  { 'error': True, 'message': 'unknown error' } ), 500 )
    (authenticated, message, http_code, username) = is_authenticated( )
    
    if not authenticated:
        return make_response( jsonify ( { 'error': True, 'message': message } ), http_code )
    else:
        post_data = request.get_json(silent=True)
        if post_data:
            csrf_in_post = post_data.get('csrf_token', None)
            csrf_in_cookie = request.cookies.get('csrf_token')
            if DBConfigHandler.is_uuid_valid( csrf_in_cookie ) and DBConfigHandler.is_uuid_valid( csrf_in_post ) and csrf_in_cookie == csrf_in_post: 
                if DBConfigHandler.validate_config_object( post_data ):
                    dbch.set_config( post_data )
                    return make_response( jsonify ( { 'error': False, 'message': 'Config set' } ), 200 )
                else:
                    return make_response( jsonify ( { 'error': True, 'message': 'Config validation error' } ), 400 )
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'CSRF problem', 'err_type': 'csrf_problem' } ), 400 )
    
    return response
    
@app.route('/api/v1/get_challenge')
@nocache
def get_challenge():
    #TODO: anti-hammer
    if dbch.is_ip_list_allowed( get_list_of_possible_client_ips() ):
        return make_response( jsonify( { 'error': False, 'message':'', 'challenge' : dbch.generate_challenge_response( ) } ), 200 )
    else:
        return make_response( jsonify( { 'error': True, 'message':'IP disallowed' } ), 401)

@app.route('/api/v1/login', methods=['POST'] )
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
                                (authenticated, message, http_code, username_authenticated) = is_authenticated( )
                                if authenticated:
                                    session_id = request.cookies.get('session_id', None)
                                    dbch.remove_specific_user_session( session_id )
                                
                                response = make_response( jsonify ( { 'error': False, 'pass_OK': True, 'message': 'Login successful.' } ), 200 )
                                dbch.set_auth_token( response, username )
                            else:
                                response = make_response( jsonify ( { 'error': True, 'pass_OK': False, 'message': 'Login failed with supplied username/pass.' } ), 401 )
                        else:
                            response = make_response( jsonify ( { 'error': True, 'message': 'Bad challenge received.' } ), 400 )
                    else:
                        response = make_response( jsonify ( { 'error': True, 'message': 'Invalid password format.' } ), 400 )    
                else:
                    response = make_response( jsonify ( { 'error': True, 'message': 'Invalid username format.' } ), 400 )
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'username,password or challenge parameters must be set in POST request.' } ), 400 )
    else:
        response = make_response( jsonify( { 'error': True, 'message': 'IP disallowed' } ), 401 )
    
    return response

@app.route('/api/v1/set_pass', methods=['POST'] )
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
                                    response = make_response( jsonify( { 'error': False, 'message': 'Password set.' } ), 200 )
                                else:
                                    response = make_response( jsonify( { 'error': True, 'message': 'Failed to set password.' } ), 500 )
                        else:
                            # An initial admin password has been set - so check the user is authenticated before allowing a password change
                            (authenticated, message, http_code, username_authenticated) = is_authenticated( )
                            if not authenticated:
                                return make_response( jsonify ( { 'error': True, 'message': message, 'err_type': 'auth_failure' } ), http_code )
                            else:
                                # We have just tested the user can correctly authenticate with this username
                                
                                # If the user is trying to change their own password and they can verify their original password
                                if not username_postdata:
                                    if original_password:
                                        if dbch.verify_password( username_authenticated, original_password ):
                                            dbch.change_pass( username_authenticated, new_password )
                                            response = make_response( jsonify( { 'error': False, 'message': 'Password changed.' } ), 200 )
                                        else:
                                            response = make_response( jsonify ( { 'error': True, 'message': 'Failed to verify original password', 'err_type': 'oiginal_pass_failure' } ), 401 )
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
                                                        if dbch.set_pass( username_postdata, 'viewer', new_password ):
                                                            response = make_response( jsonify( { 'error': False, 'message': 'Password set.' } ), 200 )
                                                        else:
                                                            response = make_response( jsonify( { 'error': False, 'message': 'Failed to set password.' } ), 500 )
                                                    else:
                                                        response = make_response( jsonify( { 'error': True, 'message': 'Error, user already exists','err_type': 'user_exists' } ), 400 )
                                                else:
                                                    response = make_response( jsonify( { 'error': True, 'message': 'Error, cant set own user pass','err_type': 'no_set_own_user' } ), 400 )
                                            else:
                                                response = make_response( jsonify ( { 'error': True, 'message': 'Not authorized to set password for a different user', 'err_type': 'bad_group' } ), 401 )                    
                            
                    else:
                        response = make_response( jsonify ( { 'error': True, 'message': 'Bad challenge received.', 'err_type': 'bad_challenge' } ), 400 )
                else:
                    response = make_response( jsonify ( { 'error': True, 'message': 'username,new-password and challenge parameters must be set in POST request.', 'err_type': 'bad_post' } ), 400 )
            else:
                response = make_response( jsonify ( { 'error': True, 'message': 'CSRF parameter or cookie problem', 'err_type': 'csrf_problem' } ), 400 )    
        else:
            response = make_response( jsonify ( { 'error': True, 'message': 'JSON parse error', 'err_type': 'json_parse' } ), 400 )
    else:
        response = make_response( jsonify( { 'error': True, 'message': 'IP disallowed', 'err_type': 'ip_block' } ), 401 )
    
    return response

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])
    

@app.route('/')
def index():
    csrf_token = request.cookies.get('csrf_token')

    if not csrf_token:
        # If no token exists, generate a new one
        csrf_token = str(uuid.uuid4())

    response = make_response(render_template('index.html', csrf_token=csrf_token))
    # TODO: set Secure=True when HTTPS
    if 'csrf_token' not in request.cookies:
        response.set_cookie('csrf_token', csrf_token, httponly=True, secure=False, samesite='Strict')

    return response


if __name__ == '__main__':
    
    ch = CameraHandler()
    print(ch.enumerate_resolutions(0))
    
    dbch = DBConfigHandler("security_cam_state.sqlite")
    serve(app, host='0.0.0.0', port=5000)
    

