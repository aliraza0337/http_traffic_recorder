# http_traffic_recorder
This proxy + recorder, records the http/https objects of the webpages being requested from the browser.

## How to use http_traffic_recorder

1. Configure the proxy and run it i.e. ip, port and data folder in recorder.py
2. Configure your browser to use the proxy
3. Visit the webpage you want to record.



## For https 

1. Configure the proxy and run it i.e. ip, port and data folder in recorder.py
2. It would create a certificate file ca.pem in the same folder
3. Add that certificate to the your browser
4. Configure your browser to use the proxy
5. Visit the webpage you want to record.


``The proxy code is adapted from a python proxy I found on GitHub``




