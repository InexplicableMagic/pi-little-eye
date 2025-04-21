<img align="right" width="200" src="docs/security-camera-with-raspberry.jpg">
An open source security camera for the Raspberry Pi using the official camera modules.<br><br>

- Viewable on all devices with a browser.
- No app required. All phones supported.
- No cloud. No subscriptions. No Telemetry.
- Image can be rotated and time stamped
- Video can be streamed to other devices e.g. for storage
- Supports multiple user accounts
- Supports IP whitelists and block lists
- Runs over https

# Installation

These instructions are for the regular version of the Raspberry Pi OS 64-bit bookworm edition upwards. 

The raspberry pi must have an official camera module attached (any version). The project does not work with USB cameras. See here for [raspberry pi camera installation instructions](https://leoncode.co.uk/articles/installing-the-raspberry-pi-camera-module/).

To install into a Python virtual env:

```
git clone https://github.com/InexplicableMagic/raspberry-pi-security-camera/
cd raspberry-pi-security-camera

python -m venv camera-env --system-site-packages
source camera-env/bin/activate
pip install -r requirements.txt
```

The ```--system-site-packages``` option allows the venv to use the globally installed Python system packages. Particularly this is for picamera2 which should be installed by default and does not seem to install particularly easily into a venv.

# Usage

To start the camera:

```
source camera-env/bin/activate
./camera_server.py
```

This will start the camera on port 5220 by default. You can change the port with the ```--port``` option.

Access the camera via a web browser like this. Note, the camera runs over TLS/SSL (https) and is not accessible via http:

```https://your-raspberry-pi:5220/```

When first connecting you will receive a **certificate warning**. This is entirely expected and is because a self-signed certificate is being used. Just click through it by whatever means is provided in your browser. Often the button you need to click to ignore the message is tiny and obscure to avoid people not reading it. On Chrome it's called "Advanced". Once you have clicked through it once you won't see the message again. If you are unsure what this message means, see the [self-signed certifiate section](#Self-Signed Certificate) below for an explanation.

The default host interface is ```0.0.0.0``` which is for access from any IPv4 network interface and should be fine for most purposes. However, if you want to start the camera on the IPv6 interface it can be done with this option: ```--host ::```.


### Self-Signed Certificate

When connecting to the camera for the first time, your brower will display a large fearsome looking message proclaiming that the connection is "not secure" or some such wording. Don't worry, the connection **is encrypted** with TLS (https) to at least the same standard as every other https connection, and possibly better. What the message is saying is that your browser is unable to verify who owns the camera.

<img width="200" src="docs/chrome-mobile-connection-not-secure.png">

When you connect to your bank over the web, how do you know that your bank actually owns the server you are connecting to? This is achieved by having a "trusted" 3rd party counter-sign that the certificate presented by the bank's server does in fact belong to the bank. In this case we have not done that step because it involves either money or a beaurocratic verification process. Instead the camera auto-generates what's called a "self-signed" certificate which does not bear the counter-signatory from the 3rd party that your browser expects. While you definitely shouldn't click through the message if you are trying to connect to your bank (and that's why it's so loud and bold) in this case it's fine because we already know who owns the camera - you do. In this instance there is no concern about who owns the device.

If you have a browser valid certificate for your camera, you can supply it on the command line and you won't get the message. However, if you're only ever going to be using the camera yourself, there is little point in going to that trouble as it won't do anything to enhance security over a self-signed certificate. All it does is get rid of the warning. Once you've clicked through it once, the browser will remember your decision and you won't be asked again.

