# HipChat Sample Add-on

This is a minimal HipChat Connect add-on that demonstrates the basic components of the API, and provides a minimal implementation
with no assumption in terms of framework and data storage

The implementation illustrates the Connect contract:

* Installation and uninstallation contract
* Full discoverability: No assumptions about endpoints on either side
* Getting and refreshing OAuth2 access tokens through the `client_credentials` grant type
* Using the API to send a notification into a room
* Adding a HipChat Glance or View in the HipChat Sidebar
* Opening a dialog in HipChat
* Using the HipChat JavaScript API

There is no persistence, no error handling and no dependency on a Connect framework: Although fully functional, the
focus is purely on the contracts that an add-on needs to implement. Rather verbose logging helps discover what goes
back and forth between the add-on and HipChat.

To install what you need to run the add-on:

	npm install -g bunyan
	npm install

Start ngrok, which will make your add-on running on http://localhost:4000 accessible to HipChat.com:

	ngrok 4000

Take a note of the base URL given by ngrok, for example in the following case the base URL is https://57376a36.ngrok.com: 

	ngrok                                                                                                                                       (Ctrl+C to quit)
                                                                                                                                                            
	Tunnel Status                 online                                                                                                                        
	Version                       1.7/1.7                                                                                                                       
	Forwarding                    http://57376a36.ngrok.com -> 127.0.0.1:4000                                                                                   
	Forwarding                    https://57376a36.ngrok.com -> 127.0.0.1:4000                                                                                  
	Web Interface                 127.0.0.1:4040                                                                                                                
	# Conn                        0                                                                                                                             
	Avg Conn Time                 0.00ms

Start the add-on:

    npm start | bunyan
   
Install the add-on in HipChat. You'll need to do that everytime your restart the add-on (no persistence):

* Go to www.hipchat.com/addons
* At the bottom of the page, click on "Install an integration from a descriptor URL"
* Enter the URL for the add-on descriptor, which is baseURL/descriptor, for example https://57376a36.ngrok.com/descriptor
* Choose a room to install the add-on in

To test the add-on:

* Type any message in the HipChat room, the add-on should echo the message
* On the HipChat sidebar, you should see a new Glance
* Click on the Glance to open in full view
* Use the buttons in the View

