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

# Usage



### Self-Signed Certificate

When connecting to the camera for the first time, your brower will display a large fearsome looking message proclaiming that the connection is "not secure" or some such wording. Don't worry, the connection **is encrypted** with TLS (https) to at least the same standard as every other https connection, and possibly better. What the message is saying is that your browser is unable to verify who owns the camera.

When you connect to your bank over the web, how do you know that your bank actually owns the server you are connecting to? This is achieved by having a "trusted" 3rd party counter-sign that the certificate presented by the bank's server does in fact belong to the bank. In this case we have not done that step because it involves either money or a beaurocratic verification process. Instead the camera auto-generates what's called a "self-signed" certificate which does not bear the counter-signatory from the 3rd party that your browser expects. While you definitely shouldn't click through the message if you are trying to connect to your bank (and that's why it's so loud and bold) in this case it's fine because we already know who owns the camera - you do. In this instance there is no concern about who owns the device.

If you have a browser valid certificate for your camera, you can supply it on the command line and you won't get the message. However, if you're only ever going to be using the camera yourself, there is little point in going to that trouble as it won't do anything to enhance security over a self-signed certificate. All it does is get rid of the warning. Once you've clicked through it once, the browser will remember your decision and you won't be asked again.


