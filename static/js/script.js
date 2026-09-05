
const getChallengeURL = '/api/v1/get-challenge';
const set_pass_url = '/api/v1/set-pass';
const loginURL = '/api/v1/login';
const videoURL = '/api/v1/video/mjpeg';
const testAuthStateURL = '/api/v1/test-auth-state';
const getConfigURL = '/api/v1/get-config';
const setConfigURL = '/api/v1/set-config';
const getLogsURL = '/api/v1/get-logs';
const logoutURL = '/api/v1/logout';
const generateAppKeyURL = '/api/v1/generate-app-key';
const accountManagementURL = '/api/v1/account-management';
const deleteAppKeyURL = '/api/v1/delete-app-key';
const manageLogsURL = '/api/v1/log-management';

const userTableID = 'user-table'

//TODO: Check cookies are enabled and message the user if not
function verifyCookiesEnabled() {
    if (navigator.cookieEnabled) return true;
}

function checkPasswordsMatch( pass1ID, pass2ID, messageID, buttonID, originalPassfield = null ) {
    const message = document.getElementById(messageID);
    const set_password1 = document.getElementById(pass1ID);
    const set_password2 = document.getElementById(pass2ID);
    const setPasswordButton = document.getElementById(buttonID);
    const originalPassButton = document.getElementById(originalPassfield);
    
    message.textContent = '';
    setPasswordButton.disabled = true;
   
    if(set_password1.value != '' && set_password2.value != ''){
        if (set_password1.value != set_password2.value ) {
            message.textContent = "Passwords don't match";
            message.style.color = 'red';
        }else{
            message.textContent = '';
            
            if( originalPassfield == null ){
                setPasswordButton.disabled = false;
            }else{
                
                if( originalPassButton.value === set_password1.value ){
                    message.textContent = "New pass same as original";
                    message.style.color = 'red';
                }else{
                    if( originalPassButton.value != '' && (originalPassButton.value != set_password1.value ) ){
                        message.textContent = '';
                        setPasswordButton.disabled = false;
                    }                
                }
            }
            
        }
    }
}

function checkUserPassFilledIn( userID, passID, addButtonID ){
    const userField = document.getElementById(userID);
    const passField = document.getElementById(passID);
    const addButton = document.getElementById(addButtonID);
    
    addButton.disabled = true;
    if(userField.value != '' && passField.value != ''){
        addButton.disabled = false;
    }
}

function addNewUser(){
    const new_user_name = document.getElementById('new-username-field');
    const new_user_pass = document.getElementById('new-user-password-field');
    const addNewUserInfo = document.getElementById('add-new-user-info');
    
    let accountType = "viewer"; 
    if( document.getElementById('account-type-admin').checked ){
        accountType = "admin";
    }
     
    addNewUserInfo.textContent = '';
    getChallenge()
    .then(challenge => {    
        return setPass(new_user_name.value, new_user_pass.value, accountType, challenge);
    }).then(result => {
        if( result && result.error == false ){
            resetConfigOnUI();
            new_user_pass.value='';
        }else{
            console.log("Error on adding user:"+result.message)
            addNewUserInfo.textContent = result.message;
            new_user_pass.value='';
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

function clearLogs() {
  
  const data = {
    csrf_token: csrfToken,
    full_clear: true
  };
  
  return fetch(manageLogsURL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })
  .then(response => {
    if (!response.ok) {
      console.log(response)
      throw new Error('Network error returned from clearLogs');
    }else{
        addLogsToUI();
    }
    return response.json();
  });

}


function deleteAppKey(app_key) {
  
  const data = {
    csrf_token: csrfToken,
    app_key: app_key
  };
  
  return fetch(deleteAppKeyURL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  })
  .then(response => {
    if (!response.ok) {
      console.log(response)
      throw new Error('Network error returned from deleteAppKey');
    }
    return response.json();
  });

}

function setPass(username, password, accountType, challenge, orignalPassword = null) {
  
  const data = {
    new_password: password,
    challenge: challenge,
    csrf_token: csrfToken
  };
  
  if( accountType != null){
    data.account_type = accountType
  }
  
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
      console.log('Network error returned from logout');
    }

    // If we are logging outselves out
    if(whichUser == null){
        // Should display the login screen
        setWindowVisibilityState();
        // Disconnect the video feed which may still be running behind the scenes
        const vfIMGElement = document.getElementById('video-feed');
        if(vfIMGElement){
            vfIMGElement.onerror = null;
            vfIMGElement.src="";
            vfIMGElement.remove();
        }
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
            
            //Populate admin options if config response is admin type
            if(config.users.permissions === 'admin'){

                const ipStringAllowlist = config.security.allowed_ips.allowlist.join('\n');
                const ipStringBlocklist = config.security.allowed_ips.blocklist.join('\n');
                const sanList = config.security.san_names.join('\n');
                
                const ipAllowlistTextArea = document.getElementById('allowed-ip-list');
                const ipBlocklistTextArea = document.getElementById('blocked-ip-list');
                const sanListTextArea = document.getElementById('set-san-list')
                
                ipAllowlistTextArea.value = ipStringAllowlist;
                if(config.security.enforce_ip_allowlist === true){
                    document.getElementById('allowed-ips-radio').checked = true;
                }else{
                    document.getElementById('any-ip-radio').checked = true;
                }
                
                document.getElementById('enable-blocklist-checkbox').checked = config.security.enforce_ip_blocklist
                
                ipBlocklistTextArea.value = ipStringBlocklist;

                sanListTextArea.value = sanList;

                const timestampPositionSelect = document.getElementById('timestamp-position-select');
                timestampPositionSelect.value = config.camera.timestamp_position;
                
                const displayTimestampCheckbox = document.getElementById('display-timestamp');
                displayTimestampCheckbox.checked = config.camera.display_timestamp;
                
                const timeStampScaleSelect = document.getElementById('timestamp-text-size');
                timeStampScaleSelect.value = config.camera.timestamp_scale

                const maxWifiBandwidthEntry = document.getElementById( 'max-wifi-bandwidth' );
                maxWifiBandwidthEntry.value = config.camera.max_wifi_bandwidth
                
                //TODO: Update for multiple camera support
                const cam_num = 0
                populateSelectWithResolutions( 'camera-resolutions-select', config.camera.cameras[cam_num].available_resolutions, config.camera.cameras[cam_num].current_resolution );
                const rotationSelect = document.getElementById('camera-rotation-select');
                rotationSelect.value = config.camera.cameras[cam_num].image_rotation;

                generateUserListTable( config.users.usernames, config.users.current_username, 'user-list-table' );
                generateAppKeyListTable( config.users.app_keys, 'app-key-list-table' );
            }

        }else{
            console.log("No config allowed");
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

function validationFeedbackIPTextArea(textAreaId) {
  const textArea = document.getElementById(textAreaId);
  let debounceTimeout;
  
  textArea.addEventListener('input', function() {
    clearTimeout( debounceTimeout )
    
    if (!validateIPArray(convertStringListToArray(textArea.value))) {
        textArea.style.border = '4px solid red';
    } else {
        textArea.style.border = ''; // Reset to default
        debounceTimeout = setTimeout(() => { saveConfig("security"); }, 500);
    }  
  });
}

function validateNumberInputAreaInRange( inputArea, min, max ) {
    const currentValue = Number(inputArea.value);
    if(currentValue >= min && currentValue <= max){
        inputArea.style.border = '';
        return true;
    }else{
        inputArea.style.border = '4px solid red';
        return false;
    }
}

function sanValidation(textAreaId) {
    const textArea = document.getElementById(textAreaId);
    let debounceTimeout;

    textArea.addEventListener('input', function() {
        clearTimeout(debounceTimeout);
        debounceTimeout = setTimeout(() => { saveConfig("security"); }, 500);
    })
}

function setupInputAreaNumberValidation( inputAreaId, min, max, doSaveConfig, panel=null ){
    const inputArea = document.getElementById(inputAreaId);

    let debounceTimeout;
    
    inputArea.addEventListener('input', function() {
        clearTimeout( debounceTimeout )

        debounceTimeout = setTimeout(() => {
            if( validateNumberInputAreaInRange(this, min, max) ){
                if(doSaveConfig){
                    saveConfig(panel);            
                }
            }
        }, 500);
    });
}

//null panel means get state of all panels
//Or only convert a specific panel if only that one has changed
function convertConfigUIStateToJSON(panel = null){
    const rotationSelect = document.getElementById('camera-rotation-select');
    const timeStampScaleSelect = document.getElementById('timestamp-text-size');
    const timestampPositionSelect = document.getElementById('timestamp-position-select');
    const displayTimestampCheckbox = document.getElementById('display-timestamp');
    const maxWifiBandwidthEntry = document.getElementById( 'max-wifi-bandwidth' );
   
    const postObject = { csrf_token: csrfToken }

    if( panel === null || panel === "security" ){
        const ipAllowlistTextArea = document.getElementById('allowed-ip-list');
        const ipBlocklistTextArea = document.getElementById('blocked-ip-list');
        const sanListTextArea = document.getElementById('set-san-list');

        enforce_blocklist_ips = document.getElementById('enable-blocklist-checkbox').checked
        enforce_allowlist_ips = document.getElementById('allowed-ips-radio').checked

        allowed_ip_listing_array = convertStringListToArray( ipAllowlistTextArea.value )
        blocked_ip_listing_array = convertStringListToArray( ipBlocklistTextArea.value )

        postObject.security = { allowed_ips: {} }

        if( validateIPArray( allowed_ip_listing_array ) ){
            postObject.security.allowed_ips.allowlist = allowed_ip_listing_array;
        } 

        if( validateIPArray( blocked_ip_listing_array ) ){
            postObject.security.allowed_ips.blocklist = blocked_ip_listing_array;
        }

        postObject.security.enforce_ip_blocklist = enforce_blocklist_ips;
        postObject.security.enforce_ip_allowlist = enforce_allowlist_ips;

        san_list_array = convertStringListToArray( sanListTextArea.value );
        postObject.security.san_names = san_list_array;


    }

    if( panel === null || panel === "camera" ){
        postObject.camera = {
          timestamp_scale: timeStampScaleSelect.value,
           timestamp_position: timestampPositionSelect.value,
           display_timestamp: displayTimestampCheckbox.checked,
           max_wifi_bandwidth: Number(maxWifiBandwidthEntry.value),
           //TODO: Update for multiple cameras - fixed to one at the moment
           cameras: [
               {
                   camera_number: 0,
                   selected_resolution: getSelectedResolution( 'camera-resolutions-select' ),
                   image_rotation: Number(rotationSelect.value),
               }
           ]
        }
    }
    
    return postObject;
        
    
}



function saveConfig(panel=null){
    config_state_as_json_object = convertConfigUIStateToJSON(panel)
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
    return setPass(username, password, 'admin', challenge);
  }).then(result => {
    if( result && result.error == false ){
        setWindowVisibilityState();
    }else{
        console.log("Password set error:"+result.message)
    }
  })
  .catch(error => {
    console.error('Error:', error);
  });
}


function changeCurrentUserPassword(  ) {
  const statusIcon = document.getElementById('password-change-status-icon');
  const changePassButton = document.getElementById('change-user-pass-button');
  const passChangeInfoSpan = document.getElementById('password-change-info');
  const password1Field = document.getElementById('change-password-newpass-field');
  const password2Field = document.getElementById('change-password-verify-field');
  const changePassOriginalField = document.getElementById('change-password-original-pass-field');
  
  original_password = changePassOriginalField.value;
  new_password = password1Field.value;
  
  changePassButton.disabled = true;
  passChangeInfoSpan.textContent = "";
  password1Field.value = '';
  password2Field.value = '';
  changePassOriginalField.value = '';
  
  getChallenge()
  .then(challenge => {    
    return setPass(null, new_password, null, challenge, original_password);
  }).then(result => {
    changePassButton.disabled = false;
    if( result && result.error == false ){
        elementVisibleOnTimer( statusIcon )
    }else{
        passChangeInfoSpan.textContent = "Error:"+result.message;
    }
  })
  .catch(error => {
    console.error('Error:', error);
  });
}

function login( username, password ){
    const message = document.getElementById('loginMessage');
    const loginPasswordText = document.getElementById('loginPassword');
    const loginUsernameText = document.getElementById('loginUsername');
    loginPasswordText.value = '';
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
                        loginUsernameText.value = '';
                        message.textContent = "";
                        setWindowVisibilityState();
                    }
                } else {
                    if( jsonData.pass_OK === false ){
                        loginPasswordText.value = '';
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

function generateUserListTable(data, current_username, divId) {
  const targetDiv = document.getElementById(divId);
  if (!targetDiv) return console.error(`Div with id "${divId}" not found.`);

  targetDiv.innerHTML = '';

  const container = document.createElement('div');
  container.className = 'user-card-list';

  data.forEach((userData) => {
    const isCurrentUser = userData.username === current_username;
    const isLocked = userData.disabled === 'yes';
    const isLoggedIn = userData.active_sessions === 'yes';

    const card = document.createElement('div');
    card.className = 'user-card';

    // Header (Identity details grouped on the left)
    card.innerHTML = `
      <div class="user-card-header">
        <div class="user-card-identity">
          <span class="user-card-name">${userData.username}</span>
          <span class="user-card-group">${userData.permissions}</span>
          ${isCurrentUser ? '<span class="user-card-you">(You)</span>' : ''}
        </div>
      </div>
      <div class="user-card-status-row">
        <span class="status-badge ${isLocked ? 'locked' : 'unlocked'}">
          ${isLocked ? '🔒 Locked' : '🔓 Unlocked'}
        </span>
        <span class="status-badge ${isLoggedIn ? 'logged-in' : 'logged-out'}">
          ${isLoggedIn ? '🟢 Logged In' : '⚪ Logged Out'}
        </span>
      </div>
    `;

    // Menu Toggle & Action Buttons (Only for other users)
    if (!isCurrentUser) {
      const header = card.querySelector('.user-card-header');

      // Create Three-Dot Menu Button (Pushed to far right)
      const menuBtn = document.createElement('button');
      menuBtn.className = 'menu-toggle-btn';
      menuBtn.innerHTML = '&#8942;'; // Vertical ellipsis (⋮)
      menuBtn.setAttribute('aria-label', 'Toggle action menu');
      header.appendChild(menuBtn);

      // Create Actions Row (Hidden by default)
      const actionsRow = document.createElement('div');
      actionsRow.className = 'user-card-actions hidden';

      // Toggle Visibility Event
      menuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        actionsRow.classList.toggle('hidden');
      });

      // Lock/Unlock Button
      const lockBtn = document.createElement('button');
      lockBtn.className = 'user-btn';
      lockBtn.textContent = isLocked ? 'Unlock' : 'Lock';
      lockBtn.addEventListener('click', () => {
        lockUnlockDelete(userData.username, isLocked ? 'unlock' : 'lock').then(() => resetConfigOnUI());
      });
      actionsRow.appendChild(lockBtn);

      // Logout Button (If active session)
      if (isLoggedIn) {
        const logoutBtn = document.createElement('button');
        logoutBtn.className = 'user-btn';
        logoutBtn.textContent = 'Logout';
        logoutBtn.addEventListener('click', () => {
          logout(userData.username).then(() => resetConfigOnUI());
        });
        actionsRow.appendChild(logoutBtn);
      }

      // Delete Button
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'user-btn';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', () => {
        showModal('Delete user?', () => {
          lockUnlockDelete(userData.username, 'delete').then(() => resetConfigOnUI());
        });
      });
      actionsRow.appendChild(deleteBtn);

      card.appendChild(actionsRow);
    }

    container.appendChild(card);
  });

  targetDiv.appendChild(container);
}

function generateAppKeyListTable(data, divId = 'app-key-list-table') {
  const targetDiv = document.getElementById(divId);
  if (!targetDiv) return console.error(`Div with id "${divId}" not found.`);

  targetDiv.innerHTML = '';

  if (!data || data.length === 0) {
    targetDiv.innerHTML = `<div class="empty-state">No application keys found.</div>`;
    return;
  }

  const container = document.createElement('div');
  container.className = 'user-card-list';

  data.forEach((keyData) => {
    const card = document.createElement('div');
    card.className = 'user-card app-key-card';

    card.innerHTML = `
      <div class="app-key-card-body">
        <div class="app-key-info">
          <code class="app-key-code">${keyData}</code>
        </div>
        <button class="trash-btn" title="Delete App Key" aria-label="Delete App Key">&#128465;</button>
      </div>
    `;

    // UTF-8 Trash Can Click Handler
    const deleteBtn = card.querySelector('.trash-btn');
    deleteBtn.addEventListener('click', () => {
      showModal(`Delete App Key "${keyData}"?`, () => {
        deleteAppKey(keyData).then(() => resetConfigOnUI());
      });
    });

    container.appendChild(card);
  });

  targetDiv.appendChild(container);
}


function populateSelectWithResolutions(selectName, allResolutions, currentResolution) {
    // Access the select element by its ID
    const selectElement = document.getElementById(selectName);

    // Clear any existing options
    selectElement.innerHTML = '';

    // Iterate over the list of resolutions
    allResolutions.forEach(resolution => {
        // Create an option element
        const optionElement = document.createElement('option');

        // Set the text and value of the option element
        optionElement.textContent = `${resolution.resolution[0]} x ${resolution.resolution[1]}`;
        optionElement.value = `${resolution.resolution[0]}x${resolution.resolution[1]}`;
        
        if (currentResolution && currentResolution.resolution[0] === resolution.resolution[0] && currentResolution.resolution[1] === resolution.resolution[1]) {
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
    
    return { resolution: [width, height] };
}

function convertLogDataToHTMLTable(log_data) {
    const top_row_columns = [
        { key: 'Datestamp', col_num: 1 },
        { key: 'Username', col_num: 4 },
        { key: 'IP', col_num: 5 },
        { key: 'Level', col_num: 2 }
    ];
    
    const level_col_num = 2;
    const message_col_num = 7;

    const table = document.createElement('table');
    table.id = 'logs-table';
    table.className = 'logs-table';

    // Header Row
    const thead = table.createTHead();
    const headerRow = thead.insertRow();
    top_row_columns.forEach(column => {
        const th = document.createElement('th');
        th.textContent = column.key;
        headerRow.appendChild(th);
    });

    const tbody = table.createTBody();

    log_data.forEach(log_line => {
        // Normalize the level text for class naming (e.g., 'warning', 'error', 'info')
        const rawLevel = String(log_line[level_col_num] || '').toLowerCase().trim();
        const levelClass = `log-level-${rawLevel}`;

        // Row 1: Metadata (Datestamp, Username, IP, Level)
        const metaRow = tbody.insertRow();
        metaRow.className = `log-meta-row ${levelClass}`;

        top_row_columns.forEach(column => {
            const cell = metaRow.insertCell();
            cell.textContent = log_line[column.col_num] ?? '';
        });

        // Row 2: Message
        const messageRow = tbody.insertRow();
        messageRow.className = `log-message-row ${levelClass}`;

        const messageCell = messageRow.insertCell();
        messageCell.colSpan = top_row_columns.length;
        messageCell.textContent = log_line[message_col_num] ?? '';
    });

    return table;
}

function addLogsToUI( before_id= null){
    getLogData(before_id)
    .then( response_data => {
        if( response_data && response_data.error == false ){
            table = convertLogDataToHTMLTable( response_data.logs )
            const targetTableDiv = document.getElementById('logs-display-section');
            const logsButtonSection = document.getElementById('logs-next-prev-button-area');
            targetTableDiv.innerHTML = '';
            logsButtonSection.innerHTML = ''
            targetTableDiv.appendChild(table);
            //Whether to generate a "next" button
            
            page_from_start = response_data.page_start + response_data.page_size;
            const newerButton = document.createElement('button');
            newerButton.disabled = true
            newerButton.textContent = 'Newer';
            newerButton.addEventListener('click', function(){ addLogsToUI( before_id=page_from_start ); } );
            logsButtonSection.appendChild(newerButton);
            
            if( response_data.page_start < response_data.max_id ){
                newerButton.disabled = false;
            }
                        
            page_from_end = response_data.page_end - 1;
            const olderButton = document.createElement('button');
            olderButton.disabled = true
            olderButton.textContent = 'Older';
            olderButton.addEventListener('click', function(){ addLogsToUI( before_id=page_from_end ); } );
            logsButtonSection.appendChild(olderButton);
        
            if( response_data.page_end > response_data.min_id ){
                olderButton.disabled = false;
            }
            
            
        }
    });
    
}

function generate_appkey(){
    getChallenge()
    .then(challenge => { 
        const data = {
            challenge: challenge,
            csrf_token: csrfToken
        }
        return fetch(generateAppKeyURL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
        }).then(data => {
            return data.json().then(jsonData => {
                if(jsonData.error === false){
                    const appkeydisplay = document.getElementById('new-appkey-display-span');
                    const secretdisplay = document.getElementById('new-secret-display-span');
                    appkeydisplay.innerHTML = jsonData.appkey
                    secretdisplay.innerHTML = jsonData.secret
                    showAppKeyDisplayArea(true);
                    resetConfigOnUI();
                    
                }else{
                    console.log( jsonData )
                }
          })
            
        })
  })
  .catch(error => {
    console.error('Error:', error);
  });
}

function getLogData( before_id = null ) {
  
  url = getLogsURL
  if( before_id != null ){
    url = getLogsURL+'?from='+before_id
  }
  
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


function addEventListeners() {
    const setInitialUsername = document.getElementById('setInitialUsername');
	const setInitialPassword1 = document.getElementById('setInitialPasswordText1');
	const setInitialPassword2 = document.getElementById('setInitialPasswordText2');
	
	const changePasswordOriginal = document.getElementById('change-password-original-pass-field');
	const changePasswordPassword1 = document.getElementById('change-password-newpass-field');
	const changePasswordPassword2 = document.getElementById('change-password-verify-field');
	const changeUserPassButton = document.getElementById('change-user-pass-button');
	
	const addNewUserField = document.getElementById('new-username-field');
    const addNewUserPassField = document.getElementById('new-user-password-field');
	
	const setPasswordButton = document.getElementById('setInitialPassButton');
	const loginUsername = document.getElementById('loginUsername');
	const loginPassword = document.getElementById('loginPassword');
	const loginButton = document.getElementById('loginButton');
	
	//Enable button and provide feedback on filling in the initial admin password
	setInitialPassword1.addEventListener('input', () => checkPasswordsMatch('setInitialPasswordText1', 'setInitialPasswordText2', 'setInitialPassMessage', 'setInitialPassButton') );
	setInitialPassword2.addEventListener('input', () => checkPasswordsMatch('setInitialPasswordText1', 'setInitialPasswordText2', 'setInitialPassMessage', 'setInitialPassButton') );
	
	//Enable button and provide feedback when changing own user password in the config
    changePasswordPassword1.addEventListener('input', () => checkPasswordsMatch('change-password-newpass-field', 'change-password-verify-field', 'password-change-info', 'change-user-pass-button', originalPassfield='change-password-original-pass-field' ) );
    changePasswordPassword2.addEventListener('input', () => checkPasswordsMatch('change-password-newpass-field', 'change-password-verify-field', 'password-change-info', 'change-user-pass-button', originalPassfield='change-password-original-pass-field' ) );
	changePasswordOriginal.addEventListener('input', () => checkPasswordsMatch('change-password-newpass-field', 'change-password-verify-field', 'password-change-info', 'change-user-pass-button', originalPassfield='change-password-original-pass-field' ) );
	
	//Enable button on login screen when user/pass filled in
	loginUsername.addEventListener('input', () => checkUserPassFilledIn( 'loginUsername', 'loginPassword', 'loginButton' ) );
	loginPassword.addEventListener('input', () => checkUserPassFilledIn( 'loginUsername', 'loginPassword', 'loginButton' ) );
	
	//Enable button and provide feedback when adding a new user account in the config
	addNewUserField.addEventListener('input', () => checkUserPassFilledIn( 'new-username-field', 'new-user-password-field', 'add-new-user-button' ) );
	addNewUserPassField.addEventListener('input', () => checkUserPassFilledIn( 'new-username-field', 'new-user-password-field', 'add-new-user-button' ) );
	
	setPasswordButton.addEventListener('click', () => setInitialPassword(setInitialUsername.value, setInitialPassword1.value));
	loginButton.addEventListener('click', () => login(loginUsername.value, loginPassword.value));
    changeUserPassButton.addEventListener('click', () => changeCurrentUserPassword(  ) );
    
    /* Hamburger config menu handler */
    document.getElementById('hamburger-menu').addEventListener('click', function() {
        resetConfigOnUI();
        document.getElementById('configuration-window').style.display = 'block';
        showAppKeyDisplayArea(false);
    });

    document.getElementById('close-config-button').addEventListener('click', function() {
        document.getElementById('configuration-window').style.display = 'none';
    });
    
    document.addEventListener('DOMContentLoaded', function() {
        validationFeedbackIPTextArea('allowed-ip-list');
        validationFeedbackIPTextArea('blocked-ip-list');
        setupInputAreaNumberValidation( 'max-wifi-bandwidth', 0.1, 100000, true, "camera" );
        sanValidation( 'set-san-list' );
    });
   
    // Restart the video if the page becomes visible after previously being hidden
    document.addEventListener('visibilitychange', function() {
            if (document.visibilityState === 'visible') {
                const div = document.getElementById('main-window');
                if (div.style.display !== 'none'){
                    restartVideoFeed()
                }
            }else{
                // Drop the video image if the page becomes invisible to save bandwidth
                const videoImg = document.getElementById('video-feed');
                if( videoImg ){
                    // Need to set the video src to blank to disconnect the video
                    // Removing the video element is not sufficient. It keeps downloading
                    // in the backgroud
                    videoImg.onerror = null;
                    videoImg.src="";
                    videoImg.remove();
                }
            }
     });
}

function restartVideoFeed() {       
    const videoContainer = document.getElementById('video-container');
    
    // Clear container and create new image element
    videoContainer.innerHTML = '';
    
    const img = document.createElement('img');
    img.src = videoURL + '?nocache=' + new Date().getTime();
    img.id = "video-feed";
    
    // If the video image cannot be displayed, print an error
    img.onerror = function() {
        console.log("Cannot start video");
        
        const vfIMGElement = document.getElementById('video-feed');
        if (vfIMGElement) {
            vfIMGElement.onerror = null;
            vfIMGElement.src = "";
            vfIMGElement.remove();
        }
        
        videoContainer.innerHTML = '';
        
        var errorSpan = document.createElement('span');
        errorSpan.textContent = "Error: Unable to contact camera. Check network and refresh.";
        errorSpan.setAttribute('id', 'video-error-span');
        errorSpan.style.color = 'white';
        videoContainer.appendChild(errorSpan);
    };
    
    videoContainer.appendChild(img);
}

// Determine if the user is authenticated - used to choose which window to display
function get_auth_state(){

    return getChallenge()
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
            if (response.ok) {
                     return response.json();
            }else{
                console.log("Error getting auth state");
            }
            
        }).catch(error => {
            message.textContent = `Network error on trying to login: ${error.message}`
        });
     }).catch(error => {
        message.textContent = `Failure during contacting camera: ${error.message}`
    });
        
}

// Set the message on the screen displayed prior to first connecting to the camera
function setInitialWindowMessageText( msg ){
    var initialMessage = document.getElementById("initial-message");
    initialMessage.textContent = msg;
}

// Display an element for a specific period of time then make it invisible
function elementVisibleOnTimer(imageElement, visibleTime=3000) {
    imageElement.style.display = 'initial';

    setTimeout(function() {
        imageElement.style.display = 'none';
    }, visibleTime);
}

// Set which window is visible to the user based on the result of the "test-auth-state" REST method call
// e.g. whether the video should be displayed or whether the user needs to login first
function setWindowVisibilityState() {
    const initialMessageWindowDiv = document.getElementById('boot-message-window');
    const initialAdminPassWindowDiv = document.getElementById('set-initial-admin-password-window');
    const loginWindowDiv = document.getElementById('login-window');
    const mainWindowDiv = document.getElementById('main-window');
    const configWindowDiv = document.getElementById('configuration-window');
    
    setInitialWindowMessageText( "Contacting camera ..." )

    get_auth_state()
    .then( auth_state => {
        
        if(auth_state.auth_state === 'set_initial_password'){
            initialMessageWindowDiv.style.display = 'none';
            initialAdminPassWindowDiv.style.display = 'block';
            loginWindowDiv.style.display = 'none';
            mainWindowDiv.style.display = 'none';
            configWindowDiv.style.display = 'none';
        }
        
        if(auth_state.auth_state === 'login_required'){
            initialMessageWindowDiv.style.display = 'none';
            initialAdminPassWindowDiv.style.display = 'none';
            loginWindowDiv.style.display = 'block';
            mainWindowDiv.style.display = 'none';
            configWindowDiv.style.display = 'none';
        }
        
        if(auth_state.auth_state === 'authenticated'){
            initialMessageWindowDiv.style.display = 'none';
            initialAdminPassWindowDiv.style.display = 'none';
            loginWindowDiv.style.display = 'none';
            mainWindowDiv.style.display = 'block';
            configWindowDiv.style.display = 'none';
            
            const standardConfigWindowDiv = document.getElementById('standard-config-panel');
            const securityConfigWindowDiv = document.getElementById('security-panel');
            const cameraConfigWindowDiv = document.getElementById('camera-config-panel');
            const logsWindowDiv = document.getElementById('logs-panel');
            const userManagementDiv = document.getElementById('user-management-panel');
            
            const addUserSectionDiv = document.getElementById('user-management-section');
            const appKeySectionDiv = document.getElementById('app-key-management-section');
            
            if(auth_state.permissions === 'admin'){
                // Enable all config options if the user is an admin
                securityConfigWindowDiv.style.display = 'none';
                cameraConfigWindowDiv.style.display = 'none';
                logsWindowDiv.style.display = 'none';
                
                userManagementDiv.style.display = 'block';
                addUserSectionDiv.style.display = 'block';
                appKeySectionDiv.style.display = 'block';
            }else{
                // Hide unavailable config options if the user does not have permissions
                securityConfigWindowDiv.style.display = 'none';
                cameraConfigWindowDiv.style.display = 'none';
                logsWindowDiv.style.display = 'none';
                
                userManagementDiv.style.display = 'block';
                addUserSectionDiv.style.display = 'none';
                appKeySectionDiv.style.display = 'none';
                
            }
            
            resetConfigOnUI();
            restartVideoFeed();
        }
        
        if(auth_state.auth_state === 'access_denied'){
            setInitialWindowMessageText( "Access Denied" )
            initialAdminPassWindowDiv.style.display = 'none';
            loginWindowDiv.style.display = 'none';
            mainWindowDiv.style.display = 'none';
            configWindowDiv.style.display = 'none';
            initialMessageWindowDiv.style.display = 'flex';
        }
    });
}

function switchConfigPanel(whichPanel) {
        const userManagementPanel = document.getElementById('user-management-panel');
        const securityPanel = document.getElementById('security-panel');
        const cameraConfigPanel = document.getElementById('camera-config-panel');
        const logsConfigPanel = document.getElementById('logs-panel');
        
        userManagementPanel.style.display = 'none';
        securityPanel.style.display = 'none';
        cameraConfigPanel.style.display = 'none';
        logsConfigPanel.style.display = 'none';
        
        switch(whichPanel){
            case "user":
                userManagementPanel.style.display = 'block';
            break;
            case "security":
                securityPanel.style.display = 'block';
            break;
            case "camera":
                cameraConfigPanel.style.display = 'block';
            break;
            case "logs":
                addLogsToUI();
                logsConfigPanel.style.display = 'block';
            break;
        }
}

function displayClearLogModal(){
    showModal( "Clear logs?", clearLogs )
}

// Text to be displayed on the modal dialogue and a callback when the user clicks the OK button
function showModal(text, onOkCallback) {
    const modalDialogue = document.getElementById('modal-dialogue-box');
    const okBtn = document.getElementById('modal-dialogue-ok-button');
    const cancelBtn = document.getElementById('modal-dialogue-cancel-button');
    const dialogueText = document.getElementById('modal-dialogue-text');
    
    dialogueText.innerHTML = text
    modalDialogue.style.display = "flex";

    // Set the OK button callback
    okBtn.onclick = function() {
        if (onOkCallback) {
            onOkCallback();
        }
        modalDialogue.style.display = "none";
    }
    
    cancelBtn.onclick = function() {
        modalDialogue.style.display = "none";
    }
}

function showAppKeyDisplayArea(show) {
  const appKeyDisplayArea = document.getElementById('new-app-key-display-area');
  if (show) {
    appKeyDisplayArea.classList.remove('hidden');
  } else {
    appKeyDisplayArea.classList.add('hidden');
    document.getElementById('new-appkey-display-span').textContent = '';
    document.getElementById('new-secret-display-span').textContent = '';
  }
}

function copyTextFromElement(elementId, buttonEl) {
  const text = document.getElementById(elementId).textContent;
  if (!text) return;

  navigator.clipboard.writeText(text).then(() => {
    const originalText = buttonEl.textContent;
    buttonEl.textContent = 'Copied!';
    buttonEl.classList.add('copied');
    setTimeout(() => {
      buttonEl.textContent = originalText;
      buttonEl.classList.remove('copied');
    }, 1800);
  });
}
