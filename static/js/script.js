
const getChallengeURL = '/api/v1/get_challenge';
const set_pass_url = '/api/v1/set_pass';
const loginURL = '/api/v1/login';
const videoURL = '/api/v1/video_feed';
const testAuthStateURL = '/api/v1/test_auth_state';
const getConfigURL = '/api/v1/get_config';
const setConfigURL = '/api/v1/set_config';
const getLogsURL = '/api/v1/get_logs';
const logoutURL = '/api/v1/logout';
const accountManagementURL = '/api/v1/account_management';

const userTableID = 'user-table'

//TODO: Check cookies are enabled and message the user if not
function verifyCookiesEnabled() {
    if (navigator.cookieEnabled) return true;
}

function checkPasswords( pass1ID, pass2ID, messageID, buttonID ) {
    const message = document.getElementById(messageID);
    const set_password1 = document.getElementById(pass1ID);
    const set_password2 = document.getElementById(pass2ID);
    const setPasswordButton = document.getElementById(buttonID); 
    if (set_password1.value === set_password2.value && set_password1.value !== '') {
        message.textContent = "Passwords match";
        message.style.color = "green";
        setPasswordButton.disabled = false;
    } else {
        message.textContent = "Passwords do not match or are empty";
        message.style.color = "red";
        setPasswordButton.disabled = true;
    }
}

function addNewUser(){
    const new_user_name = document.getElementById('new-username');
    const new_user_pass = document.getElementById('new-user-password');
    getChallenge()
    .then(challenge => {    
        return setPass(new_user_name.value, new_user_pass.value, challenge);
    }).then(result => {
        if( result && result.error == false ){
            console.log("New user added.")
        }else{
            console.log("Error on adding user:"+result.message)
        }
    })
  .catch(error => {
    console.error('Error:', error);
  });
}

function lockUnlockDelete(username, action) {
  
  const data = {
    username: username,
    csrf_token: csrfToken,
    action: action
  };
  
  return fetch(accountManagementURL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })
  .then(response => {
    if (!response.ok) {
      console.log(response)
      throw new Error('Network error returned from lockUnlockDelete');
    }
    return response.json();
  });

}


function setPass(username, password, challenge, orignalPassword = null) {
  
  const data = {
    new_password: password,
    challenge: challenge,
    csrf_token: csrfToken
  };
  
  if(orignalPassword !== null){
    data.original_password = orignalPassword
  }
  
  if(username !== null){
    data.username = username
  }

  return fetch(set_pass_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })
  .then(response => {
    if (!response.ok) {
      console.log(response)
      throw new Error('Network error returned from set_pass');
    }
    return response.json();
  });

}

function logout( whichUser = null ){
    data = {}
    if(whichUser != null ){
        data = { 'username': whichUser }
    }
    return fetch( logoutURL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
  }).then(response => {
    if (!response.ok) {
      console.log(response)
      throw new Error('Network error returned from logout');
    }
    return response.json();
  });
}

function getChallenge(){
    return restGetCallNoParams(getChallengeURL)
        .then(data => {
            if(data.error === true){
                console.error("Error fetching challenge:", data.message);
                return null;   
            }else{
                return data.challenge || null;
            }
        })
        .catch(error => {
            console.error("Error fetching challenge:", error);
            return null;
        });
}

function restGetCallNoParams(url) {
  return new Promise((resolve, reject) => {
    fetch(url)
      .then(response => {
        return response.json();
      })
      .then(data => {
        if (data) {
          resolve(data);
        } else {
          throw new Error('Data not found in the response');
        }
      })
      .catch(error => {
        reject(error);
      });
  });
}

function resetConfigOnUI(){
    getConfig()
    .then( config => {
        if(config && 'error' in config && config.error === false) {
            console.log(config)
            const ipStringWhitelist = config.allowed_ips.whitelisted.join('\n');
            const ipTextArea = document.getElementById('allowed-ip-list');
            ipTextArea.value = ipStringWhitelist;
            if(config.enforce_ip_whitelist === true){
                document.getElementById('allowed-ips-radio').checked = true;
            }else{
                document.getElementById('any-ip-radio').checked = true;
            }
            generateUserList( config.usernames, config.current_username, 'user-list-table' )
            populateSelectWithResolutions( 'camera-resolutions-select', config.available_camera_resolutions, config.current_camera_resolution )
        }else{
            console.log("No config allowed")
        }
    });
}

function isValidIPWithWildcard(ip) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){0,3}\*$/
  const ipv6Regex = /^(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:(?:[a-fA-F\d]{1,4})\:){0,7}(?:\*|(?:[a-fA-F\d]{1,3})\*))$/;

  return (ipv4Regex.test(ip) || ipv6Regex.test(ip)) && ( ip != '*' );
}

function validateIPArray(ipArray) {
   return ipArray.every(isValidIPWithWildcard);
}

function convertStringListToArray( text ){
    return text.split(/\r?\n/).map(item => item.trim()).filter(item => item !== '');
}

function validationFeedbackIPTextArea(textArea) {
  const isValid = validateIPArray(convertStringListToArray( textArea.value ));
  if (!isValid) {
    textArea.style.border = '4px solid red';
  } else {
    textArea.style.border = ''; // Reset to default
  }  
}

function setupTextAreaValidation(textAreaId) {
  const textArea = document.getElementById(textAreaId);
  
  textArea.addEventListener('input', function() {
    validationFeedbackIPTextArea(this);
  });
}

function convertConfigUIStateToJSON(){
    const ipTextArea = document.getElementById('allowed-ip-list');
    allowed_ip_listing_array = convertStringListToArray( ipTextArea.value )
    if( validateIPArray( allowed_ip_listing_array ) ){
        enforce_whitelisted_ips = true
        if(document.getElementById('any-ip-radio').checked)
            enforce_whitelisted_ips = false
        const postObject = {
               csrf_token: csrfToken,
               allowed_ips: {
                whitelisted: allowed_ip_listing_array,
                blacklisted: []
               },
               enforce_ip_whitelist: enforce_whitelisted_ips,
               selected_resolution: getSelectedResolution( 'camera-resolutions-select' )
        };
        return postObject;
        
    }else{
        console.log("Invalid IP array")
    }
}



function saveConfig(){
    config_state_as_json_object = convertConfigUIStateToJSON()
    return fetch(setConfigURL, {
    method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(config_state_as_json_object)
  })
  .then(response => {
    if (!response.ok) {
      console.log(response)
    }
    return response.json();
  });
}



function getConfig(){
    return restGetCallNoParams( getConfigURL )
    .then(data => {
            return data || null;
        })
     .catch(error => {
        console.error("Error fetching config:", error);
            return null;
    });
}


function restGetCallNoParamsWithChallenge(url){
  getChallenge()
  .then(challenge => { 
        const data = {
            challenge: challenge
        }
        return fetch(url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
        }).then(data => {
            return(data)
        })
  })
  .catch(error => {
    console.error('Error:', error);
  });
}


function setInitialPassword(username, password) {
  getChallenge()
  .then(challenge => {    
    return setPass(username, password, challenge);
  }).then(result => {
    if( result && result.error == false ){
        console.log("Password set.")
    }else{
        console.log("Password set error:"+result.message)
    }
  })
  .catch(error => {
    console.error('Error:', error);
  });
}


function changeCurrentUserPassword(original_password, new_password) {
  getChallenge()
  .then(challenge => {    
    return setPass(null, new_password, challenge, original_password);
  }).then(result => {
    if( result && result.error == false ){
        console.log("Password set.")
    }else{
        console.log("Password set error:"+result.message)
    }
  })
  .catch(error => {
    console.error('Error:', error);
  });
}


function get_auth_state(){

    getChallenge()
    .then(challenge => {
        const data = {
            challenge: challenge
        };
        return fetch(testAuthStateURL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
        })
        .then(response => {
            
            console.log( response )
            
        }).catch(error => {
            message.textContent = `Network error on trying to login: ${error.message}`
        });
     }).catch(error => {
        message.textContent = `Failure during contacting camera: ${error.message}`
    });
        
}

function login( username, password ){
    const message = document.getElementById('loginMessage');
    getChallenge()
    .then(challenge => {
        const data = {
            username: username,
            password: password,
            challenge: challenge
        };
        return fetch(loginURL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
        })
        .then(response => {
            return response.json().then(jsonData => {
                if (response.ok) {
                    if( jsonData.pass_OK === true ){
                        console.log("Login successful");
                        message.textContent = "";
                    }
                } else {
                    if( jsonData.pass_OK === false ){
                        message.textContent = "Incorrect password or username.";
                    }else{
                        message.textContent = `Error ${jsonData.message}`;
                    }
                }

            });
        }).catch(error => {
            message.textContent = `Network error on trying to login: ${error.message}`
        });
     }).catch(error => {
        message.textContent = `Failure during contacting camera: ${error.message}`
    });
}

//Convert the list of camera users into an HTML table
//for display in the configuration options
function generateUserList(data, current_username, divId) {

  // Get the target div
  const targetDiv = document.getElementById(divId);
  if (!targetDiv) {
    console.error(`Div with id "${divId}" not found.`);
    return;
  }

  const columns = [
    { key: 'username', label: 'User' },
    { key: 'permissions', label: 'Group' },
    { key: 'disabled', label: 'Locked' },
    { key: 'active_sessions', label: 'Logged In' }
  ];

  const table = document.createElement('table');
  table.id=userTableID
  table.style.border = '1px solid black';
  table.style.borderCollapse = 'collapse';

  const thead = table.createTHead();
  const headerRow = thead.insertRow();
  columns.forEach(column => {
    const th = document.createElement('th');
    th.textContent = column.label;
    th.style.border = '1px solid black';
    th.style.padding = '5px';
    headerRow.appendChild(th);
  });

  const tbody = table.createTBody();
  data.forEach(user_data => {
    const row = tbody.insertRow();
    columns.forEach(column => {
      const cell = row.insertCell();
      cell.textContent = user_data[column.key];
      cell.style.border = '1px solid black';
      cell.style.padding = '5px';
      
      if( user_data.username != current_username ){
          if(column.key == 'username' ){
            const button = document.createElement('button');
            button.textContent = 'Delete';
            button.style.marginLeft = '5px';
            button.addEventListener('click', () => {
                lockUnlockDelete( user_data.username, 'delete' ).then ( () => {
                            console.log("Deleted user");
                            resetConfigOnUI();
                });
            });
            cell.appendChild(button);
          }
          
          if(column.key == 'active_sessions' && user_data[column.key] == 'yes'){
            const button = document.createElement('button');
            button.textContent = 'Logout';
            button.style.marginLeft = '5px';
            button.addEventListener('click', () => {
                logout( whichUser=user_data.username ).then ( () => {
                    console.log("logged out");
                    resetConfigOnUI()
                });
            });
            cell.appendChild(button);
           }

          if(column.key == 'disabled' ){
            const button = document.createElement('button');
            button.style.marginLeft = '5px';
            
                if( user_data[column.key] == 'yes' ){
                    button.textContent = 'Unlock';
                    button.addEventListener('click', () => {
                        lockUnlockDelete( user_data.username, 'unlock' ).then ( () => {
                            console.log("unlocked");
                            resetConfigOnUI();
                        });
                    });
                }else{
                    button.textContent = 'Lock';
                    button.addEventListener('click', () => {
                       lockUnlockDelete( user_data.username, 'lock' ).then ( () => {
                            console.log("locked");
                            resetConfigOnUI();
                        });
                    });
                }
                cell.appendChild(button);
           }
           
       }
    
  });
  });

  // Clear the target div and append the table
  targetDiv.innerHTML = '';
  targetDiv.appendChild(table);
}


function populateSelectWithResolutions(selectName, resolutions, currentResolution) {
    // Access the select element by its ID
    const selectElement = document.getElementById(selectName);

    // Clear any existing options
    selectElement.innerHTML = '';

    // Iterate over the list of resolutions
    resolutions.forEach(resolution => {
        // Create an option element
        const optionElement = document.createElement('option');

        // Set the text and value of the option element
        optionElement.textContent = `${resolution[0]} x ${resolution[1]}`;
        optionElement.value = `${resolution[0]}x${resolution[1]}`;
        
        if (currentResolution && currentResolution[0] === resolution[0] && currentResolution[1] === resolution[1]) {
            optionElement.selected = true;
        }

        // Append the option element to the select element
        selectElement.appendChild(optionElement);
    });
}

function getSelectedResolution(selectName) {
    const selectElement = document.getElementById(selectName);
    
    const selectedOption = selectElement.options[selectElement.selectedIndex];
    
    if (!selectedOption) {
        return null;
    }
    
    const [width, height] = selectedOption.value.split('x').map(Number);
    
    return [width, height];
}


function addEventListeners() {
    const setInitialUsername = document.getElementById('setInitialUsername');
	const setInitialPassword1 = document.getElementById('setInitialPasswordText1');
	const setInitialPassword2 = document.getElementById('setInitialPasswordText2');
	
	const changePasswordOriginal = document.getElementById('changeOriginalText');
	const changePasswordPassword1 = document.getElementById('changePassText1');
	const changePasswordPassword2 = document.getElementById('changePassText2');
	const changeUserPassButton = document.getElementById('change-user-pass-button');
	
	const setPasswordButton = document.getElementById('setInitialPassButton');
	const loginUsername = document.getElementById('loginUsername');
	const loginPassword = document.getElementById('loginPassword');
	const loginButton = document.getElementById('loginButton');
	
	setInitialPassword1.addEventListener('input', () => checkPasswords('setInitialPasswordText1', 'setInitialPasswordText2', 'setInitialPassMessage', 'setInitialPassButton') );
	setInitialPassword2.addEventListener('input', () => checkPasswords('setInitialPasswordText1', 'setInitialPasswordText2', 'setInitialPassMessage', 'setInitialPassButton') );
	setPasswordButton.addEventListener('click', () => setInitialPassword(setInitialUsername.value, setInitialPassword1.value));
	loginButton.addEventListener('click', () => login(loginUsername.value, loginPassword.value));
    changeUserPassButton.addEventListener('click', () => changeCurrentUserPassword( changePasswordOriginal.value, changePasswordPassword1.value ) );
      
    document.addEventListener('DOMContentLoaded', function() {
        setupTextAreaValidation('allowed-ip-list');
    });

    //Attempt to start the video feed if the video DIV is visible
    //Restart the video if the page becomes visible (e.g. user clicks the back button)	
	window.addEventListener('pageshow', function(event) {
    if (document.visibilityState === 'visible') {
            console.log("restart video")
            const div = document.getElementById('video-container');
            if (div.style.display !== 'none'){
                restartVideoFeed()
            }
      }
    });
}

function restartVideoFeed() {
    getChallenge()
    .then(challenge => {    
        // Append the challenge as a GET parameter to the videoURL
        const urlWithChallenge = `${videoURL}?challenge=${encodeURIComponent(challenge)}`;
               
        // Create an img element
        const img = document.createElement('img');
        
        // Set the src attribute to the URL with the challenge parameter
        img.src = urlWithChallenge;
        img.id = "video-feed"
        
        // Append the img element to the video container
        const videoContainer = document.getElementById('video-container')
        const vfIMGElement = document.getElementById('video-feed');
        if(vfIMGElement){
            vfIMGElement.remove()
        }
        
        videoContainer.appendChild(img);
        
        // Add an error handler for the image
        img.onerror = () => {
            console.error('Failed to load the video stream');
        };
    })
    .catch(error => console.error('Error:', error));
}

